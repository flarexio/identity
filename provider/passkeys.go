package provider

import (
	"context"
	"errors"
	"fmt"
)

// TokenVerifier is the part of passkeys.Service this package needs.
type TokenVerifier interface {
	VerifySubject(token string) (string, error)
}

// Passkeys verifies tokens the Passkeys API issues after a successful
// WebAuthn ceremony. The subject is the WebAuthn user handle, which identity
// sets to the user's own ID at registration.
func Passkeys(svc TokenVerifier) Verifier {
	return VerifierFunc(func(ctx context.Context, credential string) (*Identity, error) {
		if svc == nil {
			return nil, errors.New("passkeys not configured")
		}

		subject, err := svc.VerifySubject(credential)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredential, err)
		}

		return &Identity{Subject: subject}, nil
	})
}
