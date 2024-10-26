package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go/micro"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/model"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/persistence"
	"github.com/flarexio/identity/policy"

	transHTTP "github.com/flarexio/identity/transport/http"
	transPubSub "github.com/flarexio/identity/transport/pubsub"
)

var (
	Version   string = "0.0.0"
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
			&cli.StringFlag{
				Name:    "nats",
				EnvVars: []string{"NATS_URL"},
				Value:   "wss://nats.flarex.io",
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
	svc = identity.LoggingMiddleware(log)(svc)

	// Add Endpoints
	endpoints := identity.EndpointSet{
		Register:         identity.RegisterEndpoint(svc),
		SignIn:           identity.SignInEndpoint(svc),
		OTPVerify:        identity.OTPVerifyEndpoint(svc),
		AddSocialAccount: identity.AddSocialAccountEndpoint(svc),
	}

	passkeysEndpoints := passkeys.EndpointSet{
		InitializeRegistration: passkeys.InitializeRegistrationEndpoint(svc),
		FinalizeRegistration:   passkeys.FinalizeRegistrationEndpoint(svc),
		InitializeLogin:        passkeys.InitializeLoginEndpoint(svc),
		FinalizeLogin:          passkeys.FinalizeLoginEndpoint(svc),
	}

	// Add Transports

	// Add PubSub Transports and Event Sourcing
	var ps pubsub.NATSPubSub
	{
		log := log.With(
			zap.String("infra", "pubsub"),
			zap.String("provider", cfg.EventBus.Provider.String()),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		natsURL := cli.String("nats")
		creds := conf.Path + "/user.creds"

		natsPS, err := pubsub.NewNATSPubSub(natsURL, cfg.Name, creds)
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

		// Add Event Sourcing
		// SUB users.>
		endpoint := identity.EventEndpoint(svc)
		handler := transPubSub.EventHandler(endpoint)

		natsPS.PullConsume(consumer, handler)

		ps = natsPS
	}

	events.ReplaceGlobals(ps)

	policy, err := policy.NewRegoPolicy(ctx, conf.Path)
	if err != nil {
		return err
	}

	// Add PubSub Transport
	{
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

		// SUB identity.signin
		signInHandler := transPubSub.SignInHandler(endpoints.SignIn)
		root.AddEndpoint("signin", signInHandler)
	}

	// Add HTTP Transport
	r := gin.Default()

	// GET /.well-known/webauthn
	r.GET("/.well-known/webauthn", func(c *gin.Context) {
		c.JSON(http.StatusOK,
			gin.H{"origins": cfg.Providers.Passkeys.Origins})
	})

	auth := transHTTP.Authorizator(policy)

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

		// POST /passkeys/registration/initialize
		apiV1.POST("/passkeys/registration/initialize",
			passkeys.InitializeRegistrationHandler(passkeysEndpoints.InitializeRegistration))

		// POST /passkeys/registration/finalize
		apiV1.POST("/passkeys/registration/finalize",
			passkeys.FinalizeRegistrationHandler(passkeysEndpoints.FinalizeRegistration))

		// POST /passkeys/login/initialize
		apiV1.POST("/passkeys/login/initialize",
			passkeys.InitializeLoginHandler(passkeysEndpoints.InitializeLogin))

		// POST /passkeys/login/finalize
		apiV1.POST("/passkeys/login/finalize",
			passkeys.FinalizeLoginHandler(passkeysEndpoints.FinalizeLogin))
	}

	go r.Run(":" + strconv.Itoa(conf.Port))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sign := <-quit

	log.Info("shutdown", zap.String("singal", sign.String()))
	return nil
}
