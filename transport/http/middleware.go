package http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/flarexio/core/policy"
)

type Claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`

	// PasskeyUserID is the subject's id at the passkey provider. A relying
	// party that gates an action behind a passkey has no other way to tell
	// whether the assertion it verified belongs to the token's subject.
	// Absent when the user has no passkey linked.
	PasskeyUserID string `json:"passkey_user_id,omitempty"`
}

func (c *Claims) Map() map[string]any {
	return map[string]any{
		"sub":   c.Subject,
		"roles": c.Roles,
	}
}

type Who byte

const (
	Owner Who = 1 << iota
	Group
	Others
	Admin
	All
)

type GinAuth func(rule string, who ...Who) gin.HandlerFunc

func Authorizator(policy policy.Policy) GinAuth {
	return func(rule string, who ...Who) gin.HandlerFunc {
		rules := strings.Split(rule, ".")
		domain := rules[0]
		action := rules[1]

		var flags byte
		for _, w := range who {
			flags = flags | byte(w)
		}

		return func(c *gin.Context) {
			var claims Claims
			if err := ParseToken(c, &claims); err != nil {
				unauthorized(c, http.StatusUnauthorized, err)
				return
			}

			input := map[string]any{
				"domain":    domain,
				"action":    action,
				"who_flags": flags,
				"claims":    claims.Map(),
			}

			if username := c.Param("user"); username != "" {
				input["object"] = username
			}

			ctx := c.Request.Context()
			allowed, err := policy.Eval(ctx, input)
			if err != nil {
				unauthorized(c, http.StatusExpectationFailed, err)
				return
			}

			if !allowed {
				unauthorized(c, http.StatusForbidden, errors.New("forbidden"))
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
			c.Abort()
			c.String(http.StatusUnauthorized, "client certificate required")
			return
		}

		cert := tlsState.PeerCertificates[0]

		for _, ou := range cert.Subject.OrganizationalUnit {
			if _, ok := allowed[ou]; ok {
				c.Next()
				return
			}
		}

		c.Abort()
		c.String(http.StatusForbidden, "client certificate not authorized")
	}
}
