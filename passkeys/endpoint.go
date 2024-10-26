package passkeys

import (
	"context"
	"errors"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-webauthn/webauthn/protocol"
)

type EndpointSet struct {
	InitializeRegistration endpoint.Endpoint
	FinalizeRegistration   endpoint.Endpoint
	InitializeLogin        endpoint.Endpoint
	FinalizeLogin          endpoint.Endpoint
}

type InitializeRegistrationRequest struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

func InitializeRegistrationEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(*InitializeRegistrationRequest)
		if !ok {
			return nil, errors.New("invalid type")
		}

		opts, err := svc.InitializeRegistration(req.UserID, req.Username)
		if err != nil {
			return nil, err
		}

		return opts, err
	}
}

func FinalizeRegistrationEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(*protocol.ParsedCredentialCreationData)
		if !ok {
			return nil, errors.New("invalid type")
		}

		token, err := svc.FinalizeRegistration(req)
		if err != nil {
			return nil, err
		}

		return token, nil
	}
}

type InitializeLoginRequest struct {
	UserID string `json:"user_id"`
}

type InitializeLoginResponse struct {
	Response  protocol.PublicKeyCredentialRequestOptions `json:"publicKey"`
	Mediation string                                     `json:"mediation"`
}

func InitializeLoginEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(*InitializeLoginRequest)
		if !ok {
			return nil, errors.New("invalid type")
		}

		opts, mediation, err := svc.InitializeLogin(req.UserID)
		if err != nil {
			return nil, err
		}

		resp := &InitializeLoginResponse{
			Response:  opts.Response,
			Mediation: mediation,
		}

		return resp, err
	}
}

func FinalizeLoginEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(*protocol.ParsedCredentialAssertionData)
		if !ok {
			return nil, errors.New("invalid type")
		}

		token, err := svc.FinalizeLogin(req)
		if err != nil {
			return nil, err
		}

		return token, nil
	}
}

type InitializeTransactionRequest struct {
	UserID          string `json:"user_id"`
	TransactionID   string `json:"transaction_id"`
	TransactionData any    `json:"transaction_data"`
}
