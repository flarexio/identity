package http

import (
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

func Init(i, a string, secret []byte) {
	issuer = i
	audience = a

	keyFn = func(t *jwt.Token) (any, error) {
		return secret, nil
	}
}

func ParseToken(ctx *gin.Context, claims jwt.Claims) error {
	if audience == "" || keyFn == nil {
		return ErrTokenNotInit
	}

	tokenStr := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(tokenStr, "Bearer ") {
		return ErrInvalidToken
	}

	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	_, err := jwt.ParseWithClaims(tokenStr, claims, keyFn,
		jwt.WithAudience(audience),
		jwt.WithLeeway(10*time.Second),
	)

	return err
}
