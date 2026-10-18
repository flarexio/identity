package http

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/flarexio/core/policy"
	"github.com/flarexio/identity/token"
)

// Claims is kept for relying parties that decode identity's tokens with it.
type Claims = token.Claims

const claimsKey = "identity.claims"

type Who byte

const (
	Owner Who = 1 << iota
	Group
	Others
	Admin
	All
)

type GinAuth func(rule string, who ...Who) gin.HandlerFunc

// Authenticate requires a valid access token and stores its claims.
func Authenticate(tokens *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authenticate(c, tokens) {
			c.Next()
		}
	}
}

// authenticate verifies the bearer token, aborting the request if it is
// missing or invalid. It must not call c.Next: Authorizator uses it before
// its own policy check.
func authenticate(c *gin.Context, tokens *token.Issuer) bool {
	signed, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	if !ok {
		Fail(c, token.ErrInvalidToken)
		return false
	}

	claims, err := tokens.Parse(signed)
	if err != nil {
		Fail(c, err)
		return false
	}

	c.Set(claimsKey, claims)
	return true
}

// ClaimsFrom returns the claims Authenticate stored.
func ClaimsFrom(c *gin.Context) (*token.Claims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}

	claims, ok := v.(*token.Claims)
	return claims, ok
}

// Authorizator authenticates the request, then evaluates rule
// ("domain.action") against the policy, with the :user path parameter as
// the object.
func Authorizator(tokens *token.Issuer, policy policy.Policy) GinAuth {
	return func(rule string, who ...Who) gin.HandlerFunc {
		domain, action, ok := strings.Cut(rule, ".")
		if !ok {
			panic("authorizator: rule must be domain.action: " + rule)
		}

		var flags byte
		for _, w := range who {
			flags = flags | byte(w)
		}

		return func(c *gin.Context) {
			if !authenticate(c, tokens) {
				return
			}

			claims, _ := ClaimsFrom(c)

			input := map[string]any{
				"domain":    domain,
				"action":    action,
				"who_flags": flags,
				"claims":    claims.Map(),
			}

			if username := c.Param("user"); username != "" {
				input["object"] = username
			}

			allowed, err := policy.Eval(c.Request.Context(), input)
			if err != nil {
				Fail(c, err)
				return
			}

			if !allowed {
				c.Error(errors.New("forbidden"))
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{"forbidden", "forbidden"})
				return
			}

			c.Next()
		}
	}
}

// RequireClientOU restricts an mTLS route to peers whose client certificate
// Subject.OrganizationalUnit intersects allowedOUs. If allowedOUs is empty,
// every request is rejected (fail closed) rather than left unrestricted.
func RequireClientOU(allowedOUs []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOUs))
	for _, ou := range allowedOUs {
		allowed[ou] = struct{}{}
	}

	return func(c *gin.Context) {
		tlsState := c.Request.TLS
		if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{"client_certificate_required", "client certificate required"})
			return
		}

		cert := tlsState.PeerCertificates[0]

		for _, ou := range cert.Subject.OrganizationalUnit {
			if _, ok := allowed[ou]; ok {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{"client_certificate_forbidden", "client certificate not authorized"})
	}
}

// SecurityHeaders sets the headers every response gets. Pages (the
// frontend) set their own, looser, Content-Security-Policy over this one.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Next()
	}
}

// NoStore keeps tokens and account data out of caches.
func NoStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

// BodyLimit caps request bodies; nothing identity accepts comes close.
func BodyLimit(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		}
		c.Next()
	}
}

// SameOrigin rejects requests a browser sent from another site. Routes that
// act on the session cookie, or set it, rely on it against CSRF, on top of
// SameSite. Clients that are not browsers send neither header and pass.
func SameOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if site := c.GetHeader("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" && site != "none" {
				forbidCrossSite(c)
				return
			}
		} else if origin := c.GetHeader("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != c.Request.Host {
				forbidCrossSite(c)
				return
			}
		}

		c.Next()
	}
}

func forbidCrossSite(c *gin.Context) {
	c.Error(errors.New("cross-site request"))
	c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{"cross_site", "cross-site request refused"})
}

// RateLimit allows each client address burst requests, refilled at r per
// second. Client addresses come from gin's ClientIP, so they can only be
// spoofed through proxies listed in http.trustedProxies.
func RateLimit(r rate.Limit, burst int) gin.HandlerFunc {
	type client struct {
		limiter *rate.Limiter
		seen    time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
		swept   = time.Now()
	)

	return func(c *gin.Context) {
		now := time.Now()
		ip := c.ClientIP()

		mu.Lock()
		if now.Sub(swept) > time.Minute {
			for k, v := range clients {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(clients, k)
				}
			}
			swept = now
		}

		cl, ok := clients[ip]
		if !ok {
			cl = &client{limiter: rate.NewLimiter(r, burst)}
			clients[ip] = cl
		}
		cl.seen = now
		allowed := cl.limiter.Allow()
		mu.Unlock()

		if !allowed {
			c.Header("Retry-After", "10")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, ErrorResponse{"rate_limited", "too many requests"})
			return
		}

		c.Next()
	}
}

// AccessLog logs each request by path only: query strings carry OAuth codes
// and state, which must not end up in logs.
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
		}

		if errs := c.Errors.ByType(gin.ErrorTypePrivate); len(errs) > 0 {
			fields = append(fields, zap.String("error", errs.String()))
		}

		switch status := c.Writer.Status(); {
		case status >= 500:
			log.Error("request", fields...)
		case status >= 400:
			log.Warn("request", fields...)
		default:
			log.Info("request", fields...)
		}
	}
}
