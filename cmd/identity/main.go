package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
	"github.com/flarexio/identity/persistence/inmem"
	"github.com/flarexio/identity/provider"
	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/user"

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
			&cli.BoolFlag{
				Name:    "dev",
				Usage:   "Human-readable debug logging",
				EnvVars: []string{"IDENTITY_DEV"},
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func newLogger(dev bool) (*zap.Logger, error) {
	if dev {
		return zap.NewDevelopment()
	}

	gin.SetMode(gin.ReleaseMode)
	return zap.NewProduction()
}

func newProviders(cfg conf.Providers, passkeysSvc passkeys.Service) map[user.SocialProvider]identity.Provider {
	providers := make(map[user.SocialProvider]identity.Provider)

	if id := cfg.Google.Client.ID; id != "" {
		providers[user.GOOGLE] = identity.Provider{
			Verifier:      provider.Google(id),
			OpensAccounts: true,
		}
	}

	if ch := cfg.LINE.Channel; ch.ID != "" {
		providers[user.LINE] = identity.Provider{
			Verifier:      provider.LINE(ch.ID, ch.Secret),
			OpensAccounts: true,
		}
	}

	if passkeysSvc != nil {
		providers[user.PASSKEYS] = identity.Provider{
			Verifier: provider.Passkeys(passkeysSvc),
		}
	}

	return providers
}

func run(cli *cli.Context) error {
	if err := conf.LoadEnv(cli); err != nil {
		return err
	}

	cfg, err := conf.LoadConfig()
	if err != nil {
		return err
	}
	conf.ReplaceGlobals(cfg)

	log, err := newLogger(cli.Bool("dev"))
	if err != nil {
		return err
	}
	defer log.Sync()

	zap.ReplaceGlobals(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ctx = context.WithValue(ctx, model.Logger, log)

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

	// Add Service and Middlewares
	passkeysSvc, err := passkeys.NewService(cfg.Providers.Passkeys)
	if err != nil {
		return err
	}

	var svc identity.Service
	svc = identity.NewService(repo, newProviders(cfg.Providers, passkeysSvc), passkeysSvc)
	svc = identity.LoggingMiddleware(log)(svc)

	var projection identity.EventHandler
	projection = identity.NewEventHandler(repo)
	projection = identity.EventLoggingMiddleware(log)(projection)

	renew := cfg.JWT.Timeout
	if cfg.JWT.Refresh.Enabled {
		renew = cfg.JWT.Refresh.Maximum
	}

	tokens, err := token.NewIssuer(token.Config{
		Issuer:      cfg.BaseURL,
		Audiences:   cfg.JWT.Audiences,
		Key:         cfg.JWT.Privkey,
		Lifetime:    cfg.JWT.Timeout,
		RenewWindow: renew,
		Admins:      cfg.JWT.Admins,
	})
	if err != nil {
		return err
	}

	// Add Endpoints
	endpoints := identity.NewEndpointSet(svc, tokens)

	// Add PubSub Transports and Event Sourcing
	var ps pubsub.NATSPubSub
	{
		log := log.With(
			zap.String("infra", "pubsub"),
			zap.String("provider", cfg.EventBus.Provider.String()),
		)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		natsURL := cli.String("nats")
		creds := filepath.Join(conf.Path, "user.creds")

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
		endpoint := identity.EventEndpoint(projection)
		handler := transPubSub.EventHandler(endpoint, log)

		if err := natsPS.PullConsume(consumer, handler); err != nil {
			log.Error(err.Error())
			return err
		}

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
	permissionsPath := filepath.Join(conf.Path, "permissions.json")
	rbac, err := policy.NewRegoPolicy(ctx, permissionsPath)
	if err != nil {
		return err
	}

	webDir := cfg.HTTP.Web
	if webDir == "" {
		webDir = filepath.Join(conf.Path, "web")
	}
	webDir, hasWeb := transHTTP.FrontendDir(webDir)
	if hasWeb {
		log.Info("serving frontend", zap.String("dir", webDir))
	}

	s := &server{
		cfg:       cfg,
		log:       log,
		endpoints: endpoints,
		tokens:    tokens,
		policy:    rbac,
		passkeys:  passkeysSvc,
		webDir:    webDir,
	}

	router, err := s.publicRouter()
	if err != nil {
		return err
	}

	errc := make(chan error, 2)
	servers := []*http.Server{newHTTPServer(":"+strconv.Itoa(conf.Port), router)}

	go func() {
		log.Info("listening", zap.String("addr", servers[0].Addr))
		errc <- servers[0].ListenAndServe()
	}()

	// Run mTLS server
	if cli.Bool("mtls-enabled") {
		challenges, err := inmem.NewChallengeStore()
		if err != nil {
			return err
		}
		defer challenges.Close()

		router, err := s.mtlsRouter(challenges)
		if err != nil {
			return err
		}

		certs := filepath.Join(conf.Path, "certs")

		srv, err := newMTLSServer(fmt.Sprintf(":%d", cli.Int("mtls-port")), router, filepath.Join(certs, "ca.crt"))
		if err != nil {
			return err
		}
		servers = append(servers, srv)

		go func() {
			log.Info("listening (mTLS)", zap.String("addr", srv.Addr))
			errc <- srv.ListenAndServeTLS(filepath.Join(certs, "server.crt"), filepath.Join(certs, "server.key"))
		}()
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", zap.Error(err))
			shutdown(servers)
			return err
		}
	}

	shutdown(servers)
	return nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
}

func newMTLSServer(addr string, handler http.Handler, caFile string) (*http.Server, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}

	srv := newHTTPServer(addr, handler)
	srv.TLSConfig = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	return srv, nil
}

func shutdown(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, srv := range servers {
		srv.Shutdown(ctx)
	}
}
