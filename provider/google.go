package provider

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/idtoken"
)

// Google verifies Google ID tokens issued to clientID.
func Google(clientID string) Verifier {
	return VerifierFunc(func(ctx context.Context, credential string) (*Identity, error) {
		if clientID == "" {
			return nil, errors.New("google client id not configured")
		}

		payload, err := idtoken.Validate(ctx, credential, clientID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredential, err)
		}

		if payload.Subject == "" {
			return nil, fmt.Errorf("%w: no subject", ErrInvalidCredential)
		}

		id := &Identity{Subject: payload.Subject}
		id.Name, _ = payload.Claims["name"].(string)
		id.Picture, _ = payload.Claims["picture"].(string)

		if verified, _ := payload.Claims["email_verified"].(bool); verified {
			id.Email, _ = payload.Claims["email"].(string)
		}

		return id, nil
	})
}
