package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go/micro"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/model"
	"github.com/flarexio/core/policy"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/persistence"
	"github.com/flarexio/identity/transport/line"

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

var genkeyCmd = &cli.Command{
	Name:  "genkey",
	Usage: "Generate a new ed25519 key pair",
	Action: func(ctx *cli.Context) error {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}

		basedPriv := base64.StdEncoding.EncodeToString(priv)
		basedPub := base64.StdEncoding.EncodeToString(pub)

		fmt.Printf("Public Key: %s\n", basedPub)
		fmt.Printf("Private Key: %s\n", basedPriv)

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
		Commands: []*cli.Command{versionCmd, genkeyCmd},
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
			&cli.BoolFlag{
				Name:    "mtls-enabled",
				Usage:   "Enable mTLS service",
				Value:   false,
				EnvVars: []string{"IDENTITY_MTLS_ENABLED"},
			},
			&cli.IntFlag{
				Name:    "mtls-port",
				Usage:   "Specifies the mTLS service port",
				Value:   8443,
				EnvVars: []string{"IDENTITY_MTLS_PORT"},
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
	passkeysSvc, err := passkeys.NewService(cfg.Providers.Passkeys)
	if err != nil {
		return err
	}

	svc := identity.NewService(repo, passkeysSvc, cfg.Providers)
	svc = identity.LoggingMiddleware(log)(svc)

	// Add Endpoints
	endpoints := identity.EndpointSet{
		Register:         identity.RegisterEndpoint(svc),
		SignIn:           identity.SignInEndpoint(svc),
		OTPVerify:        identity.OTPVerifyEndpoint(svc),
		AddSocialAccount: identity.AddSocialAccountEndpoint(svc),
		User:             identity.UserEndpoint(svc),
		RegisterPasskey:  identity.RegisterPasskeyEndpoint(svc),
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

	// GET /.well-known/jwks.json
	r.GET("/.well-known/jwks.json", transHTTP.JWKHandler)

	// GET /.well-known/webauthn
	r.GET("/.well-known/webauthn", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"origins": cfg.Providers.Passkeys.Origins})
	})

	if provider := cfg.Providers.LINE; provider.Channel.ID != "" {
		line.SetConfig(provider)

		// GET /auth/line
		r.GET("/auth/line", line.LoginAuthURLHandler())

		// GET /auth/line/callback
		r.GET("/auth/line/callback", line.AuthCallback(endpoints.SignIn))
	}

	transHTTP.Init(
		cfg.BaseURL,          // issuer
		cfg.JWT.Audiences[0], // audience
		cfg.JWT.Privkey,      // ed25519 private key
	)

	permissionsPath := filepath.Join(conf.Path, "permissions.json")
	policy, err := policy.NewRegoPolicy(ctx, permissionsPath)
	if err != nil {
		return err
	}

	auth := transHTTP.Authorizator(policy)

	apiV1 := r.Group("/identity/v1")
	{
		// PATCH /signin
		apiV1.PATCH("/signin", transHTTP.SignInHandler(endpoints.SignIn))

		// POST /users
		apiV1.POST("/users", transHTTP.RegisterHandler(endpoints.Register))

		// PATCH /users/:user/verify
		apiV1.POST("/users/:user/verify",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.OTPVerifyHandler(endpoints.OTPVerify))

		// PUT /users/:user/socials
		apiV1.PUT("/users/:user/socials",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.AddSocialAccountHandler(endpoints.AddSocialAccount))

		// POST /users/:user/passkeys/register
		apiV1.POST("/users/:user/passkeys/register",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.RegisterPasskeyHandler(endpoints.RegisterPasskey))

		// GET /token/user
		apiV1.GET("/token/user", transHTTP.UserHandler(endpoints.User))

		// PATCH /token/refresh
		apiV1.PATCH("/token/refresh", transHTTP.RefreshHandler)

		// POST /passkeys/registration
		{
			endpoint := passkeys.FinalizeRegistrationEndpoint(passkeysSvc)
			apiV1.POST("/passkeys/registration", passkeys.FinalizeRegistrationHandler(endpoint))
		}
	}

	go r.Run(":" + strconv.Itoa(conf.Port))

	// Run mTLS server
	if cli.Bool("mtls-enabled") {
		r := gin.Default()
		r.GET("/.well-known/jwks.json", transHTTP.JWKHandler)
		r.GET("/users/:subject", transHTTP.DirectUserHandler(endpoints.User))

		addr := fmt.Sprintf(":%d", cli.Int("mtls-port"))

		certFile := conf.Path + "/certs/server.crt"
		keyFile := conf.Path + "/certs/server.key"
		caFile := conf.Path + "/certs/ca.crt"

		go runMTLSServer(r, addr, certFile, keyFile, caFile)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sign := <-quit

	log.Info("shutdown", zap.String("singal", sign.String()))
	return nil
}

// 啟動 mTLS 的 Gin server
func runMTLSServer(router http.Handler, addr, certFile, keyFile, caFile string) error {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server := &http.Server{
		Addr:    addr,
		Handler: router,
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}
