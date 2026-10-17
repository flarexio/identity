package provider

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	channelID     = "1234567890"
	channelSecret = "channel-secret"
)

func lineToken(t *testing.T, method jwt.SigningMethod, key any, mutate func(*lineClaims)) string {
	claims := lineClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://access.line.me",
			Subject:   "U1234",
			Audience:  jwt.ClaimStrings{channelID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: "n0nce",
		Name:  "Line User",
		Email: "line@example.com",
	}
	if mutate != nil {
		mutate(&claims)
	}

	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return s
}

func TestLINE(t *testing.T) {
	v := LINE(channelID, channelSecret)
	ctx := WithNonce(context.Background(), "n0nce")
	secret := []byte(channelSecret)

	id, err := v.Verify(ctx, lineToken(t, jwt.SigningMethodHS256, secret, nil))
	require.NoError(t, err)
	assert.Equal(t, "U1234", id.Subject)
	assert.Equal(t, "line@example.com", id.Email)

	cases := map[string]struct {
		ctx   context.Context
		token string
	}{
		"no nonce in context": {context.Background(), lineToken(t, jwt.SigningMethodHS256, secret, nil)},
		"nonce mismatch":      {ctx, lineToken(t, jwt.SigningMethodHS256, secret, func(c *lineClaims) { c.Nonce = "other" })},
		"wrong audience":      {ctx, lineToken(t, jwt.SigningMethodHS256, secret, func(c *lineClaims) { c.Audience = jwt.ClaimStrings{"other"} })},
		"wrong issuer":        {ctx, lineToken(t, jwt.SigningMethodHS256, secret, func(c *lineClaims) { c.Issuer = "https://evil.example" })},
		"expired":             {ctx, lineToken(t, jwt.SigningMethodHS256, secret, func(c *lineClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) })},
		"no expiry":           {ctx, lineToken(t, jwt.SigningMethodHS256, secret, func(c *lineClaims) { c.ExpiresAt = nil })},
		"wrong secret":        {ctx, lineToken(t, jwt.SigningMethodHS256, []byte("guess"), nil)},
		"other hmac alg":      {ctx, lineToken(t, jwt.SigningMethodHS512, secret, nil)},
		"unsigned":            {ctx, lineToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, nil)},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(tc.ctx, tc.token)
			assert.ErrorIs(t, err, ErrInvalidCredential)
		})
	}
}
