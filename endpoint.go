package identity

import (
	"context"
	"errors"
	"time"

	"github.com/go-kit/kit/endpoint"

	"github.com/flarexio/identity/user"
)

type EndpointSet struct {
	Register            endpoint.Endpoint
	SignIn              endpoint.Endpoint
	OTPVerify           endpoint.Endpoint
	AddSocialAccount    endpoint.Endpoint
	RemoveSocialAccount endpoint.Endpoint
	RegisterPasskey     endpoint.Endpoint
	User                endpoint.Endpoint
	UserBySocialID      endpoint.Endpoint
	DeleteUser          endpoint.Endpoint
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

		return svc.Register(req.Username, req.Name, req.Email)
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

		return svc.OTPVerify(req.OTP, req.Username)
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

		u, err := svc.SignIn(ctx, req.Credential, req.Provider)
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

		return svc.AddSocialAccount(req.Credential, req.Provider, req.Username)
	}
}

type RemoveSocialAccountRequest struct {
	Provider user.SocialProvider
	SocialID user.SocialID
	Username string
}

func RemoveSocialAccountEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		req, ok := request.(RemoveSocialAccountRequest)
		if !ok {
			return nil, errors.New("invalid request")
		}

		return svc.RemoveSocialAccount(req.Provider, req.SocialID, req.Username)
	}
}

func RegisterPasskeyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		username, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}

		return svc.RegisterPasskey(username)
	}
}

func UserEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		username, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}

		return svc.User(username)
	}
}

func UserBySocialIDEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		socialID, ok := request.(user.SocialID)
		if !ok {
			return nil, errors.New("invalid request")
		}

		return svc.UserBySocialID(socialID)
	}
}

func DeleteUserEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (response any, err error) {
		username, ok := request.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}

		return nil, svc.DeleteUser(username)
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
		case *user.UserSocialAccountRemovedEvent:
			err = handler.UserSocialAccountRemovedHandler(e)
		case *user.UserDeletedEvent:
			err = handler.UserDeletedHandler(e)
		default:
			err = errors.New("invalid request")
		}

		return nil, err
	}
}
