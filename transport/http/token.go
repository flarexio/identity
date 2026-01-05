package http

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/flarexio/identity/conf"
)

var (
	ErrTokenNotInit = errors.New("token not initialized")
	ErrInvalidToken = errors.New("invalid token")
)

var (
	issuer   string
	audience string
	keyFn    jwt.Keyfunc
)

func Init(i, a string, privkey ed25519.PrivateKey) {
	issuer = i
	audience = a

	pubkey := privkey.Public().(ed25519.PublicKey)
	keyFn = func(t *jwt.Token) (any, error) {
		return pubkey, nil
	}
}

func ParseToken(ctx *gin.Context, claims jwt.Claims) error {
	if audience == "" || keyFn == nil {
		return ErrTokenNotInit
	}

	authHeader := ctx.GetHeader("Authorization")

	tokenStr, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return ErrInvalidToken
	}

	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFn,
		jwt.WithAudience(audience),
		jwt.WithLeeway(10*time.Second),
	)

	return err
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func JWKHandler(c *gin.Context) {
	cfg := conf.G()

	pub := cfg.JWT.Privkey.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)

	hash := sha256.Sum256(pub)
	kid := base64.RawURLEncoding.EncodeToString(hash[:16])

	jwk := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   x,
		Alg: "EdDSA",
		Use: "sig",
		Kid: kid,
	}

	jwkSet := JWKSet{
		Keys: []JWK{jwk},
	}

	c.JSON(http.StatusOK, jwkSet)
}
