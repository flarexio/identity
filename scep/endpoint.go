package scep

import (
	"context"
	"errors"

	"github.com/go-kit/kit/endpoint"
)

// GenerateEndpoint mints a one-time challenge for the given subject (the CN the
// device will request). Called when identity hands out an enrollment profile.
func GenerateEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		subject, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid type")
		}

		return svc.Generate(subject)
	}
}

// VerifyEndpoint consumes a challenge and returns the subject it was bound to.
// Called from the SCEPCHALLENGE webhook; a non-nil error means "deny".
func VerifyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		challenge, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid type")
		}

		return svc.Verify(challenge)
	}
}
