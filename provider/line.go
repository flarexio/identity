package provider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type lineClaims struct {
	jwt.RegisteredClaims
	Nonce   string `json:"nonce"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Email   string `json:"email"`
}

// LINE verifies LINE Login ID tokens, which are HS256-signed with the
// channel secret. The token must echo the nonce in ctx (see WithNonce), so a
// token can only be redeemed by the login flow that requested it.
func LINE(channelID, channelSecret string) Verifier {
	return VerifierFunc(func(ctx context.Context, credential string) (*Identity, error) {
		if channelID == "" || channelSecret == "" {
			return nil, errors.New("line channel not configured")
		}

		expected, ok := nonce(ctx)
		if !ok {
			return nil, fmt.Errorf("%w: no nonce to check against", ErrInvalidCredential)
		}

		keyFn := func(*jwt.Token) (any, error) {
			return []byte(channelSecret), nil
		}

		var claims lineClaims
		if _, err := jwt.ParseWithClaims(credential, &claims, keyFn,
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer("https://access.line.me"),
			jwt.WithAudience(channelID),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(10*time.Second),
		); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredential, err)
		}

		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expected)) != 1 {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidCredential)
		}

		if claims.Subject == "" {
			return nil, fmt.Errorf("%w: no subject", ErrInvalidCredential)
		}

		return &Identity{
			Subject: claims.Subject,
			Name:    claims.Name,
			Email:   claims.Email, // LINE only releases addresses it has verified
			Picture: claims.Picture,
		}, nil
	})
}
