package identity

import (
	"context"
	"errors"
	"time"

	"github.com/go-kit/kit/endpoint"

	"github.com/flarexio/identity/user"
)

type EndpointSet struct {
	Register         endpoint.Endpoint
	SignIn           endpoint.Endpoint
	OTPVerify        endpoint.Endpoint
	AddSocialAccount endpoint.Endpoint
	RegisterPasskey  endpoint.Endpoint
	User             endpoint.Endpoint
}

type RegisterRequest struct {
	Username string
	Name     string
	Email    string
}

func RegisterEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		req, ok := request.(RegisterRequest)
		if !ok {
			return nil, errors.New("invalid request")
		}

		u, err := svc.Register(req.Username, req.Name, req.Email)
		if err != nil {
			return nil, err
		}

		return u, nil
	}
}

type OTPVerifyRequest struct {
	OTP      string
	Username string
}

func OTPVerifyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		req, ok := request.(OTPVerifyRequest)
		if !ok {
			return nil, errors.New("invalid request")
		}

		u, err := svc.OTPVerify(req.OTP, req.Username)
		if err != nil {
			return nil, err
		}

		return u, nil
	}
}

type SignInRequest struct {
	Credential string
	Provider   user.SocialProvider
}

type SignInResponse struct {
	User  *user.User `json:"user"`
	Token *Token     `json:"token"`
}

type Token struct {
	Token     string    `json:"token"`
	ExpiredAt time.Time `json:"expired_at"`
}

func SignInEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		req, ok := request.(SignInRequest)
		if !ok {
			return nil, errors.New("invalid request")
		}

		u, err := svc.SignIn(req.Credential, req.Provider)
		if err != nil {
			return nil, err
		}

		resp := SignInResponse{
			User: u,
		}

		return resp, nil
	}
}

type AddSocialAccountRequest struct {
	Credential string
	Provider   user.SocialProvider
	Username   string
}

func AddSocialAccountEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		req, ok := request.(AddSocialAccountRequest)
		if !ok {
			return nil, errors.New("invalid request")
		}

		u, err := svc.AddSocialAccount(req.Credential, req.Provider, req.Username)
		if err != nil {
			return nil, err
		}

		return u, nil
	}
}

func RegisterPasskeyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		username, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}

		opts, err := svc.RegisterPasskey(username)
		if err != nil {
			return nil, err
		}

		return opts, nil
	}
}

func UserEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		username, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}

		u, err := svc.User(username)
		if err != nil {
			return nil, err
		}

		return u, nil
	}
}

func EventEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		handler, err := svc.Handler()
		if err != nil {
			return nil, err
		}

		switch e := request.(type) {
		case *user.UserRegisteredEvent:
			err = handler.UserRegisteredHandler(e)
		case *user.UserActivatedEvent:
			err = handler.UserActivatedHandler(e)
		case *user.UserSocialAccountAddedEvent:
			err = handler.UserSocialAccountAddedHandler(e)
		default:
			err = errors.New("invalid request")
		}

		return nil, err
	}
}
