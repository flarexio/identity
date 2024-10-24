package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go/micro"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ginzap "github.com/gin-contrib/zap"
	consul "github.com/hashicorp/consul/api"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/model"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/persistence"
	"github.com/flarexio/identity/policy"
	"github.com/flarexio/identity/transport"

	transHTTP "github.com/flarexio/identity/transport/http"
	transPubSub "github.com/flarexio/identity/transport/pubsub"
)

var (
	Version   string
	BuildTime string
	GitCommit string
)

var versionCmd = &cli.Command{
	Name:    "version",
	Aliases: []string{"ver", "v"},
	Usage:   "Show version",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "Show all infomation (include: Version, BuildTime, GitCommit)",
			Value:   false,
		},
	},
	Action: func(ctx *cli.Context) error {
		if !ctx.Bool("all") {
			fmt.Println(ctx.App.Version)
		} else {
			cli.ShowVersion(ctx)
		}
		return nil
	},
}

func main() {
	cli.VersionPrinter = func(cli *cli.Context) {
		fmt.Println("Version: " + cli.App.Version)
		fmt.Println("BuildTime: " + BuildTime)
		fmt.Println("GitCommit: " + GitCommit)
	}

	app := &cli.App{
		Name:     "identity",
		Usage:    "Scalable and decentralized user identity management",
		Version:  Version,
		Commands: []*cli.Command{versionCmd},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "path",
				Usage:   "Specifies the working directory",
				EnvVars: []string{"IDENTITY_PATH"},
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Specifies the HTTP service port",
				Value:   8080,
				EnvVars: []string{"IDENTITY_HTTP_PORT"},
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	time.Sleep(3000 * time.Millisecond)
}

func run(cli *cli.Context) error {
	err := conf.LoadEnv(cli)
	if err != nil {
		return err
	}

	cfg, err := conf.LoadConfig()
	if err != nil {
		return err
	}
	conf.ReplaceGlobals(cfg)

	log, err := zap.NewDevelopment()
	if err != nil {
		return err
	}
	defer log.Sync()

	zap.ReplaceGlobals(log)

	ctx := context.WithValue(context.Background(), model.Logger, log)

	// Add Persistence
	repo, err := persistence.NewUserRepository(cfg.Persistence)
	if err != nil {
		log.Error(err.Error(),
			zap.String("infra", "persistence"),
			zap.String("driver", cfg.Persistence.Driver.String()),
		)
		return err
	}
	defer repo.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Add Service and Middlewares
	svc := identity.NewService(repo, cfg.Providers)

	if cfg.Transports.LoadBalancing.Enabled {
		ch := make(chan identity.Instance, 1)
		svc = identity.ProxyingMiddleware(ctx, ch)(svc)

		go Discovery(ctx, ch, cfg)
	}

	svc = identity.LoggingMiddleware(log)(svc)

	// Add Endpoints
	endpoints := identity.EndpointSet{
		Register:         identity.RegisterEndpoint(svc),
		SignIn:           identity.SignInEndpoint(svc),
		OTPVerify:        identity.OTPVerifyEndpoint(svc),
		AddSocialAccount: identity.AddSocialAccountEndpoint(svc),
		CheckHealth:      identity.CheckHealth(svc),
	}

	// Add Transports

	// Add PubSub Transport
	var ps pubsub.NATSPubSub
	{
		log := log.With(
			zap.String("infra", "pubsub"),
			zap.String("provider", cfg.EventBus.Provider.String()),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		nats := cfg.Transports.NATS.Internal

		natsPS, err := pubsub.NewNATSPubSub(nats.URL(), cfg.Name, nats.Credentials)
		if err != nil {
			log.Error(err.Error())
			return err
		}
		defer natsPS.Close()

		log.Info("connected")

		if err := natsPS.AddJetStream(); err != nil {
			log.Error(err.Error())
			return err
		}

		users := cfg.EventBus.Users
		if err := natsPS.AddStreamAndConsumer(ctx, users); err != nil {
			log.Error(err.Error())
			return err
		}

		consumer := pubsub.ConsumerStreamPair{
			Consumer: users.Consumer.Name,
			Stream:   users.Consumer.Stream,
		}

		// SUB users.>
		endpoint := identity.EventEndpoint(svc)
		handler := transPubSub.EventHandler(endpoint)

		if err := natsPS.PullConsume(consumer, handler); err != nil {
			log.Error(err.Error())
			return err
		}

		ps = natsPS
	}

	events.ReplaceGlobals(ps)

	policy, err := policy.NewRegoPolicy(ctx, conf.Path)
	if err != nil {
		return err
	}

	if nats := cfg.Transports.NATS; nats.Enabled {
		srv, err := ps.AddService(micro.Config{
			Name:        "identity",
			Version:     Version,
			Description: "Scalable and decentralized user identity management",
			Metadata: map[string]string{
				"id": cfg.Name,
			},
		})

		if err != nil {
			return err
		}

		root := srv.AddGroup("identity")

		// TODO: reqPrefix

		// SUB identity.signin
		signInHandler := transPubSub.SignInHandler(endpoints.SignIn)
		root.AddEndpoint("signin", signInHandler)

		// SUB identity.health
		checkHealthHandler := transPubSub.CheckHealthHandler(endpoints.CheckHealth)
		root.AddEndpoint("health", checkHealthHandler)
	}

	// Add HTTP Transport
	r := gin.New()
	r.Use(ginzap.Ginzap(log, time.RFC3339, true))
	r.Use(gin.Recovery())

	auth := transHTTP.Authorizator(policy)

	r.GET("/health", transHTTP.CheckHealthHandler(endpoints.CheckHealth))

	apiV1 := r.Group("/identity/v1")
	{
		// PATCH /signin
		apiV1.PATCH("/signin", transHTTP.SignInHandler(endpoints.SignIn))

		// POST /users
		apiV1.POST("/users", transHTTP.RegisterHandler(endpoints.Register))

		// PATCH /users/:id/verify
		apiV1.POST("/users/:id/verify",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.OTPVerifyHandler(endpoints.OTPVerify),
		)

		// PUT /users/id/socials
		apiV1.POST("/users/:id/socials",
			auth("identity::users.update", transHTTP.Owner|transHTTP.Admin),
			transHTTP.AddSocialAccountHandler(endpoints.AddSocialAccount),
		)

		// PATCH /token/refresh
		apiV1.PATCH("/token/refresh", transHTTP.RefreshHandler)
	}

	go r.Run(":" + strconv.Itoa(conf.Port))

	go Registry(ctx, cfg)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sign := <-quit

	log.Info("shutdown", zap.String("singal", sign.String()))
	return nil
}

func Registry(ctx context.Context, cfg *conf.Config) {
	log, ok := ctx.Value(model.Logger).(*zap.Logger)
	if !ok {
		log = zap.L()
	}
	log = log.With(zap.String("action", "service_registry"))

	if !cfg.Transports.HTTP.Enabled && !cfg.Transports.NATS.Enabled {
		log.Warn("service registeration ignored")
		return
	}

	client, err := consul.NewClient(consul.DefaultConfig())
	if err != nil {
		log.Error(err.Error())
		return
	}

	tags := make([]string, 0)

	if Version != "" {
		tags = append(tags, Version)
	}

	service := &consul.AgentServiceRegistration{
		ID:              cfg.Name,
		Name:            "identity",
		Port:            conf.Port,
		Address:         "localhost",
		Tags:            tags,
		TaggedAddresses: make(map[string]consul.ServiceAddress),
		Meta:            make(map[string]string),
		Checks:          make(consul.AgentServiceChecks, 0),
	}

	if cfg.Transports.HTTP.Enabled {
		http := cfg.Transports.HTTP.Internal
		service.Port = http.Port
		service.Address = http.Host
		service.Tags = append(service.Tags, http.Scheme)
		service.TaggedAddresses[http.Scheme] = consul.ServiceAddress{
			Address: http.Host,
			Port:    http.Port,
		}

		if http.Health.Enabled {
			check := &consul.AgentServiceCheck{
				Interval:                       "10s",
				Timeout:                        "1s",
				HTTP:                           http.URL() + http.Health.Path,
				DeregisterCriticalServiceAfter: "60s",
			}
			service.Checks = append(service.Checks, check)
		}

		if http := cfg.Transports.HTTP.External; http != nil {
			service.Tags = append(service.Tags, http.Scheme)
			service.TaggedAddresses[http.Scheme] = consul.ServiceAddress{
				Address: http.Host,
				Port:    http.Port,
			}

			if http.Health.Enabled {
				check := &consul.AgentServiceCheck{
					Interval:                       "10s",
					Timeout:                        "1s",
					HTTP:                           http.URL() + http.Health.Path,
					DeregisterCriticalServiceAfter: "60s",
				}

				service.Checks = append(service.Checks, check)
			}
		}
	}

	if cfg.Transports.NATS.Enabled {
		nats := cfg.Transports.NATS.Internal
		service.Tags = append(service.Tags, nats.Scheme)
		service.TaggedAddresses[nats.Scheme] = consul.ServiceAddress{
			Address: nats.Host,
			Port:    nats.Port,
		}
		service.Meta["nats_request_prefix"] = cfg.Transports.NATS.ReqPrefix

		if nats.Health.Enabled {
			check := &consul.AgentServiceCheck{
				Interval: "10s",
				Timeout:  "1s",
				Args: []string{
					"/consul/script/nats-health-check",
					"--host", nats.Host,
					"--subject", nats.Health.Path,
				},
				DeregisterCriticalServiceAfter: "60s",
			}
			service.Checks = append(service.Checks, check)
		}

		if nats := cfg.Transports.NATS.External; nats != nil {
			// override
			service.TaggedAddresses[nats.Scheme] = consul.ServiceAddress{
				Address: nats.Host,
				Port:    nats.Port,
			}

			if nats.Health.Enabled {
				check := &consul.AgentServiceCheck{
					Interval: "10s",
					Timeout:  "1s",
					Args: []string{
						"/consul/script/nats-health-check",
						"--host", nats.Host,
						"--subject", nats.Health.Path,
					},
					DeregisterCriticalServiceAfter: "60s",
				}
				service.Checks = append(service.Checks, check)
			}
		}
	}

	if cfg.Transports.LoadBalancing.Enabled {
		service.Tags = append(service.Tags, "lb")
	}

	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			err := client.Agent().ServiceDeregister(service.ID)
			if err != nil {
				log.Error(err.Error())
				return
			}

			log.Info("done")
			return

		case <-ticker.C:
			_, _, err := client.Agent().Service(service.ID, nil)
			if err != nil {
				err = client.Agent().ServiceRegister(service)
				if err != nil {
					log.Error(err.Error())
					continue
				}

				log.Info("service registration")
			}
		}
	}
}

func Discovery(ctx context.Context, ch chan<- identity.Instance, cfg *conf.Config) {
	log, ok := ctx.Value(model.Logger).(*zap.Logger)
	if !ok {
		log = zap.L()
	}
	log = log.With(zap.String("action", "service_diesocvery"))

	client, err := consul.NewClient(consul.DefaultConfig())
	if err != nil {
		log.Error(err.Error(), zap.String("phase", "create_client"))
		return
	}

	session, _, err := client.Session().Create(&consul.SessionEntry{
		TTL: "60s",
	}, nil)
	if err != nil {
		log.Error(err.Error(), zap.String("phase", "create_session"))
		return
	}
	defer client.Session().Destroy(session, nil)

	query, _, err := client.PreparedQuery().Create(&consul.PreparedQueryDefinition{
		Session: session,
		Service: consul.ServiceQuery{
			Service: "identity",
		},
	}, nil)
	if err != nil {
		log.Error(err.Error(), zap.String("phase", "create_query"))
		return
	}

	instances := make(map[string]identity.Instance) // map[instanceID:tag]identity.Instance
	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Info("done")
			return

		case <-ticker.C:
			resp, _, err := client.PreparedQuery().Execute(query, nil)
			if err != nil {
				log.Error(err.Error(), zap.String("phase", "execute_query"))
				continue
			}

			alivedInstances := make(map[string]struct{})
			for _, node := range resp.Nodes {
				for _, tag := range node.Service.Tags {

					modified := false

					id := node.Service.ID + ":" + tag
					instance, ok := instances[id]
					if !ok {
						modified = true
						instance = identity.Instance{
							ID:       node.Service.ID,
							Protocol: tag,
							IsAlive:  true,
						}
					}

					switch tag {
					case "http", "https":
						// TODO

					case "nats":
						if address, ok := node.Service.TaggedAddresses["nats"]; !ok {
							log.Error("address not found")
							continue
						} else {
							if instance.Address != address.Address {
								instance.Address = address.Address
								modified = true
							}

							if instance.Port != address.Port {
								instance.Port = address.Port
								modified = true
							}
						}

						if reqPrefix, ok := node.Service.Meta["nats_request_prefix"]; !ok {
							log.Error("prefix not found")
							continue
						} else {
							if instance.RequestPrefix != reqPrefix {
								instance.RequestPrefix = reqPrefix
								modified = true
							}
						}
					}

					if modified {
						endpoints, err := transport.MakeEndpoints(instance)
						if err != nil {
							log.WithOptions(
								nop(err, transport.ErrEndpointEmpty),
							).Error(err.Error())
							continue
						}

						instance.ModifiedTime = time.Now()
						instance.Endpoints = endpoints
						instances[id] = instance

						// update identity.ProxyingMiddleware.instances
						ch <- instance
					}

					alivedInstances[id] = struct{}{}
				}
			}

			for id, instance := range instances {
				if _, ok := alivedInstances[id]; ok {
					continue
				}

				instance.IsAlive = false
				ch <- instance

				delete(instances, id)
			}

			client.Session().Renew(session, nil)
		}
	}
}

func nop(target error, errs ...error) zap.Option {
	return zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		for _, err := range errs {
			if errors.Is(err, target) {
				return zapcore.NewNopCore()
			}
		}

		return core
	})
}
