package identity

import (
	"context"
	"errors"
	"time"

	"github.com/go-kit/kit/endpoint"

	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/user"
)

var errInvalidRequest = errors.New("invalid request")

type EndpointSet struct {
	SignIn              endpoint.Endpoint
	Session             endpoint.Endpoint
	Refresh             endpoint.Endpoint
	AddSocialAccount    endpoint.Endpoint
	RemoveSocialAccount endpoint.Endpoint
	RegisterPasskey     endpoint.Endpoint
	User                endpoint.Endpoint
	UserBySocialID      endpoint.Endpoint
	DeleteUser          endpoint.Endpoint
}

func NewEndpointSet(svc Service, tokens *token.Issuer) EndpointSet {
	return EndpointSet{
		SignIn:              SignInEndpoint(svc, tokens),
		Session:             SessionEndpoint(svc, tokens),
		Refresh:             RefreshEndpoint(svc, tokens),
		AddSocialAccount:    AddSocialAccountEndpoint(svc),
		RemoveSocialAccount: RemoveSocialAccountEndpoint(svc),
		RegisterPasskey:     RegisterPasskeyEndpoint(svc),
		User:                UserEndpoint(svc),
		UserBySocialID:      UserBySocialIDEndpoint(svc, tokens),
		DeleteUser:          DeleteUserEndpoint(svc),
	}
}

type Token = token.Token

type SignInRequest struct {
	Credential string              `json:"credential"`
	Provider   user.SocialProvider `json:"provider"`
}

type SignInResponse struct {
	User  *user.User `json:"user"`
	Token *Token     `json:"token"`

	// For the browser session cookie; never part of a response body.
	Session *Token `json:"-"`
}

func SignInEndpoint(svc Service, tokens *token.Issuer) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(SignInRequest)
		if !ok {
			return nil, errInvalidRequest
		}

		u, err := svc.SignIn(ctx, req.Credential, req.Provider)
		if err != nil {
			return nil, err
		}

		return issue(tokens, u, time.Now(), true)
	}
}

func issue(tokens *token.Issuer, u *user.User, authTime time.Time, session bool) (SignInResponse, error) {
	access, err := tokens.Issue(u, authTime)
	if err != nil {
		return SignInResponse{}, err
	}

	resp := SignInResponse{User: u, Token: access}

	if session {
		resp.Session, err = tokens.IssueSession(u, authTime)
		if err != nil {
			return SignInResponse{}, err
		}
	}

	return resp, nil
}

// SessionEndpoint trades the browser's session cookie for an access token.
// The session itself is not extended: it ends at auth_time + the renew
// window, like every token issued from it.
func SessionEndpoint(svc Service, tokens *token.Issuer) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		session, ok := request.(string)
		if !ok {
			return nil, errInvalidRequest
		}

		id, authTime, err := tokens.ParseSession(session)
		if err != nil {
			return nil, err
		}

		u, err := activeUser(ctx, svc, id)
		if err != nil {
			return nil, err
		}

		return issue(tokens, u, authTime, false)
	}
}

// RefreshEndpoint reissues an access token, within the renew window of the
// original sign-in, for an account that is still active and still the one
// the token was issued to.
func RefreshEndpoint(svc Service, tokens *token.Issuer) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		claims, ok := request.(*token.Claims)
		if !ok {
			return nil, errInvalidRequest
		}

		// Tokens from before uid and auth_time existed cannot prove either.
		if claims.UserID == "" || claims.AuthTime == nil {
			return nil, token.ErrRenewExpired
		}

		authTime := claims.AuthTime.Time
		if !tokens.Renewable(authTime) {
			return nil, token.ErrRenewExpired
		}

		id, err := user.ParseID(claims.UserID)
		if err != nil {
			return nil, token.ErrInvalidToken
		}

		u, err := activeUser(ctx, svc, id)
		if err != nil {
			return nil, err
		}

		if u.Username != claims.Subject {
			return nil, token.ErrRenewExpired
		}

		return tokens.Issue(u, authTime)
	}
}

// activeUser loads the user a session or token renewal is for. An account
// that is gone or disabled just means the client has to sign in again.
func activeUser(ctx context.Context, svc Service, id user.UserID) (*user.User, error) {
	u, err := svc.ActiveUser(ctx, id)
	if errors.Is(err, user.ErrUserNotFound) || errors.Is(err, ErrAccountInactive) {
		return nil, token.ErrRenewExpired
	}

	return u, err
}

type AddSocialAccountRequest struct {
	Credential string              `json:"credential"`
	Provider   user.SocialProvider `json:"provider"`
	Username   string              `json:"-"`
}

func AddSocialAccountEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(AddSocialAccountRequest)
		if !ok {
			return nil, errInvalidRequest
		}

		return svc.AddSocialAccount(ctx, req.Credential, req.Provider, req.Username)
	}
}

type RemoveSocialAccountRequest struct {
	Provider user.SocialProvider `json:"provider"`
	SocialID user.SocialID       `json:"social_id"`
	Username string              `json:"-"`
}

func RemoveSocialAccountEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(RemoveSocialAccountRequest)
		if !ok {
			return nil, errInvalidRequest
		}

		return svc.RemoveSocialAccount(ctx, req.Provider, req.SocialID, req.Username)
	}
}

func RegisterPasskeyEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		username, ok := request.(string)
		if !ok {
			return nil, errInvalidRequest
		}

		return svc.RegisterPasskey(ctx, username)
	}
}

func UserEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		username, ok := request.(string)
		if !ok {
			return nil, errInvalidRequest
		}

		return svc.User(ctx, username)
	}
}

type UserBySocialIDRequest struct {
	Provider user.SocialProvider
	SocialID user.SocialID
}

// UserBySocialIDEndpoint mints a token for a user on behalf of a trusted
// internal service (the mTLS transport), which counts as authentication.
func UserBySocialIDEndpoint(svc Service, tokens *token.Issuer) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req, ok := request.(UserBySocialIDRequest)
		if !ok {
			return nil, errInvalidRequest
		}

		u, err := svc.UserBySocialID(ctx, req.Provider, req.SocialID)
		if err != nil {
			return nil, err
		}

		return issue(tokens, u, time.Now(), false)
	}
}

func DeleteUserEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		username, ok := request.(string)
		if !ok {
			return nil, errInvalidRequest
		}

		return nil, svc.DeleteUser(ctx, username)
	}
}

func EventEndpoint(handler EventHandler) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		switch e := request.(type) {
		case *user.UserRegisteredEvent:
			return nil, handler.UserRegisteredHandler(ctx, e)
		case *user.UserActivatedEvent:
			return nil, handler.UserActivatedHandler(ctx, e)
		case *user.UserSocialAccountAddedEvent:
			return nil, handler.UserSocialAccountAddedHandler(ctx, e)
		case *user.UserSocialAccountRemovedEvent:
			return nil, handler.UserSocialAccountRemovedHandler(ctx, e)
		case *user.UserDeletedEvent:
			return nil, handler.UserDeletedHandler(ctx, e)
		default:
			return nil, errInvalidRequest
		}
	}
}
