// Package provider verifies credentials issued by the identity providers a
// user can sign in with, reducing each to the same Identity.
package provider

import (
	"context"
	"errors"
)

// ErrInvalidCredential covers every way a credential can fail verification.
// Callers see only this; the wrapped cause is for logs.
var ErrInvalidCredential = errors.New("invalid credential")

// Identity is what a verified credential says about its holder.
type Identity struct {
	Subject string // the user's ID at the provider

	Name    string
	Email   string // empty unless the provider vouches for it
	Picture string
}

type Verifier interface {
	Verify(ctx context.Context, credential string) (*Identity, error)
}

type VerifierFunc func(ctx context.Context, credential string) (*Identity, error)

func (f VerifierFunc) Verify(ctx context.Context, credential string) (*Identity, error) {
	return f(ctx, credential)
}

type contextKey int

const nonceKey contextKey = iota

// WithNonce carries the nonce an OpenID Connect ID token must echo back.
func WithNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceKey, nonce)
}

func nonce(ctx context.Context) (string, bool) {
	n, ok := ctx.Value(nonceKey).(string)
	return n, ok && n != ""
}
