package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/flarexio/core/policy"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/scep"
	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/transport/line"

	transHTTP "github.com/flarexio/identity/transport/http"
)

const maxBody = 64 << 10

type server struct {
	cfg       *conf.Config
	log       *zap.Logger
	endpoints identity.EndpointSet
	tokens    *token.Issuer
	policy    policy.Policy
	passkeys  passkeys.Service // nil when not configured
	webDir    string           // empty when there is no frontend
}

// FrontendConfig tells the frontend which sign-in methods to offer.
type FrontendConfig struct {
	GoogleClientID string `json:"google_client_id,omitempty"`
	LINE           bool   `json:"line"`
	Passkeys       bool   `json:"passkeys"`
}

func newEngine(log *zap.Logger, trustedProxies []string) (*gin.Engine, error) {
	r := gin.New()
	r.HandleMethodNotAllowed = true

	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		return nil, err
	}

	r.Use(
		transHTTP.AccessLog(log),
		gin.Recovery(),
		transHTTP.SecurityHeaders(),
		transHTTP.BodyLimit(maxBody),
	)

	return r, nil
}

func (s *server) publicRouter() (*gin.Engine, error) {
	cfg := s.cfg

	proxies := make([]string, len(cfg.HTTP.TrustedProxies))
	for i, p := range cfg.HTTP.TrustedProxies {
		proxies[i] = p.String()
	}

	r, err := newEngine(s.log, proxies)
	if err != nil {
		return nil, err
	}

	// Signing in is where credentials get guessed and upstream APIs called.
	strict := transHTTP.RateLimit(rate.Limit(1), 10)
	relaxed := transHTTP.RateLimit(rate.Limit(10), 50)

	sameOrigin := transHTTP.SameOrigin()
	noStore := transHTTP.NoStore()
	authenticate := transHTTP.Authenticate(s.tokens)
	auth := transHTTP.Authorizator(s.tokens, s.policy)

	// GET /.well-known/jwks.json
	r.GET("/.well-known/jwks.json", transHTTP.JWKHandler(s.tokens))

	frontend := FrontendConfig{GoogleClientID: cfg.Providers.Google.Client.ID}

	if provider := cfg.Providers.LINE; provider.Channel.ID != "" {
		frontend.LINE = true

		t := line.New(provider, s.endpoints.SignIn, s.endpoints.AddSocialAccount, s.log)

		lineRoutes := r.Group("/auth/line", strict, noStore)

		// GET /auth/line
		lineRoutes.GET("", t.SignInHandler)

		// GET /auth/line/callback
		lineRoutes.GET("/callback", t.CallbackHandler)

		// GET /auth/line/link/:user
		lineRoutes.GET("/link/:user", sameOrigin,
			auth("identity::users.update", transHTTP.Owner),
			t.LinkHandler)
	}

	apiV1 := r.Group("/identity/v1", noStore)
	{
		// GET /config
		apiV1.GET("/config", func(c *gin.Context) {
			c.JSON(http.StatusOK, frontend)
		})

		// PATCH /signin
		apiV1.PATCH("/signin", strict, sameOrigin, transHTTP.SignInHandler(s.endpoints.SignIn))

		// POST /session/token
		apiV1.POST("/session/token", strict, sameOrigin, transHTTP.SessionTokenHandler(s.endpoints.Session))

		// DELETE /session
		apiV1.DELETE("/session", sameOrigin, transHTTP.SignOutHandler)

		// PATCH /token/refresh
		apiV1.PATCH("/token/refresh", strict, authenticate, transHTTP.RefreshHandler(s.endpoints.Refresh))

		users := apiV1.Group("/users/:user", relaxed)

		// GET /users/:user
		users.GET("",
			auth("identity::users.get", transHTTP.Owner),
			transHTTP.UsernameHandler(s.endpoints.User))

		// DELETE /users/:user
		users.DELETE("",
			auth("identity::users.delete", transHTTP.Owner),
			transHTTP.DeleteUserHandler(s.endpoints.DeleteUser))

		// PUT /users/:user/socials
		users.PUT("/socials",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.AddSocialAccountHandler(s.endpoints.AddSocialAccount))

		// DELETE /users/:user/socials
		users.DELETE("/socials",
			auth("identity::users.update", transHTTP.Owner),
			transHTTP.RemoveSocialAccountHandler(s.endpoints.RemoveSocialAccount))

		if s.passkeys != nil {
			frontend.Passkeys = true

			// POST /users/:user/passkeys/register
			users.POST("/passkeys/register",
				auth("identity::users.update", transHTTP.Owner),
				transHTTP.UsernameHandler(s.endpoints.RegisterPasskey))

			// POST /passkeys/registration
			apiV1.POST("/passkeys/registration", relaxed, authenticate,
				transHTTP.PasskeyFinalizeRegistrationHandler(passkeys.FinalizeRegistrationEndpoint(s.passkeys)))

			// POST /passkeys/login/initialize
			apiV1.POST("/passkeys/login/initialize", strict,
				transHTTP.PasskeyInitializeLoginHandler(passkeys.InitializeLoginEndpoint(s.passkeys)))

			// POST /passkeys/login/finalize
			apiV1.POST("/passkeys/login/finalize", strict,
				transHTTP.PasskeyFinalizeLoginHandler(passkeys.FinalizeLoginEndpoint(s.passkeys)))

			// GET /.well-known/webauthn
			r.GET("/.well-known/webauthn", func(c *gin.Context) {
				c.Header("Access-Control-Allow-Origin", "*")
				c.Header("Cross-Origin-Resource-Policy", "cross-origin")
				c.JSON(http.StatusOK, gin.H{"origins": cfg.Providers.Passkeys.Origins})
			})
		}
	}

	if s.webDir != "" {
		r.NoRoute(transHTTP.Frontend(s.webDir, "/identity", "/auth", "/.well-known"))
	} else {
		r.NoRoute(func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusNotFound, transHTTP.ErrorResponse{Error: "not_found", Message: "not found"})
		})
	}

	return r, nil
}

// mtlsRouter serves internal services. TLS has already verified the client
// certificate against the CA; each route then checks what the certificate
// is for.
func (s *server) mtlsRouter(challenges scep.Store) (*gin.Engine, error) {
	r, err := newEngine(s.log, nil)
	if err != nil {
		return nil, err
	}

	r.Use(transHTTP.NoStore())

	r.GET("/.well-known/jwks.json", transHTTP.JWKHandler(s.tokens))

	requireClientOU := transHTTP.RequireClientOU(s.cfg.MTLS.AllowedOUs)

	// GET /users/:subject
	r.GET("/users/:subject", requireClientOU,
		transHTTP.DirectUserBySocialIDHandler(s.endpoints.UserBySocialID))

	scepSvc := scep.NewService(challenges, 0)

	// POST /scep/challenge/generate
	//
	// Restricted to service certificates: devices hold certificates from the
	// same CA, and one that could mint challenges could enroll as anyone.
	r.POST("/scep/challenge/generate", requireClientOU,
		transHTTP.SCEPGenerateHandler(scep.GenerateEndpoint(scepSvc)))

	// POST /scep/challenge/verify
	r.POST("/scep/challenge/verify",
		transHTTP.SCEPVerifyHandler(scep.VerifyEndpoint(scepSvc), s.cfg.SCEP, s.log))

	return r, nil
}
