package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"google.golang.org/api/idtoken"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/user"
)

var (
	ErrProviderNotSupported = errors.New("provider not supported")
	ErrAudienceNotFound     = errors.New("audience not found")
	ErrEmailNotFound        = errors.New("email not found")
	ErrNameNotFound         = errors.New("name not found")
	ErrPictureNotFound      = errors.New("picture not found")
)

type Service interface {
	Register(username string, name string, email string) (*user.User, error)
	OTPVerify(otp string, username string) (*user.User, error)
	SignIn(credential string, provider user.SocialProvider) (*user.User, error)
	AddSocialAccount(credential string, provider user.SocialProvider, username string) (*user.User, error)
	RegisterPasskey(username string) (*protocol.CredentialCreation, error)
	Handler() (EventHandler, error)
}

type EventHandler interface {
	UserRegisteredHandler(e *user.UserRegisteredEvent) error
	UserActivatedHandler(e *user.UserActivatedEvent) error
	UserSocialAccountAddedHandler(e *user.UserSocialAccountAddedEvent) error
}

type ServiceMiddleware func(Service) Service

func NewService(users user.Repository, passkeys passkeys.Service, cfg conf.Providers) Service {
	return &service{cfg, users, passkeys}
}

type service struct {
	cfg      conf.Providers
	users    user.Repository
	passkeys passkeys.Service
}

func (svc *service) Register(username string, name string, email string) (*user.User, error) {
	_, err := svc.users.FindByUsername(username)
	if err == nil {
		return nil, errors.New("user exists")
	}

	u := user.NewUser(username, name, email)
	defer u.Notify()

	return u, nil
}

func (svc *service) OTPVerify(otp string, username string) (*user.User, error) {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return nil, err
	}

	// TODO: otp verify
	u.Activate()
	defer u.Notify()

	return u, nil
}

func (svc *service) SignIn(credential string, provider user.SocialProvider) (*user.User, error) {
	switch provider {
	case user.GOOGLE:
		return svc.signInWithGoogle(credential)
	case user.PASSKEYS:
		return svc.signInWithPasskeys(credential)
	}

	return nil, ErrProviderNotSupported
}

func (svc *service) signInWithGoogle(token string) (*user.User, error) {
	audience := svc.cfg.Google.Client.ID
	if audience == "" {
		return nil, ErrAudienceNotFound
	}

	ctx := context.Background()
	payload, err := idtoken.Validate(ctx, token, audience)
	if err != nil {
		return nil, err
	}

	socialID := user.SocialID(payload.Subject)
	u, err := svc.users.FindBySocialID(socialID)
	if err != nil {
		if !errors.Is(err, user.ErrUserNotFound) {
			return nil, err
		}

		// New User
		email, ok := payload.Claims["email"].(string)
		if !ok {
			return nil, ErrEmailNotFound
		}

		name, ok := payload.Claims["name"].(string)
		if !ok {
			return nil, ErrNameNotFound
		}

		username := strings.Split(email, "@")[0]

		u = user.NewUser(username, name, email)

		picture, ok := payload.Claims["picture"].(string)
		if ok {
			u.Avatar = picture
		}

		u.Register()
		u.Activate()
		u.AddSocialAccount(user.GOOGLE, socialID)

		defer u.Notify()
	}

	// TODO: check if user exists and update from google

	return u, nil
}

func (svc *service) signInWithPasskeys(signed string) (*user.User, error) {
	token, err := svc.passkeys.VerifyToken(signed)
	if err != nil {
		return nil, err
	}

	subject, err := token.Claims.GetSubject()
	if err != nil {
		return nil, err
	}

	socialID := user.SocialID(subject)
	return svc.users.FindBySocialID(socialID)
}

func (svc *service) AddSocialAccount(credential string, provider user.SocialProvider, username string) (*user.User, error) {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return nil, err
	}

	var subject string
	switch provider {
	case user.GOOGLE:
		audience := svc.cfg.Google.Client.ID
		if audience == "" {
			return nil, ErrAudienceNotFound
		}

		ctx := context.Background()
		payload, err := idtoken.Validate(ctx, credential, audience)
		if err != nil {
			return nil, err
		}

		subject = payload.Subject

	case user.PASSKEYS:
		token, err := svc.passkeys.VerifyToken(credential)
		if err != nil {
			return nil, err
		}

		sub, err := token.Claims.GetSubject()
		if err != nil {
			return nil, err
		}

		subject = sub

	default:
		return nil, ErrProviderNotSupported
	}

	socialID := user.SocialID(subject)
	_, err = svc.users.FindBySocialID(socialID)
	if err == nil {
		return nil, errors.New("account exists")
	}

	u.AddSocialAccount(provider, socialID)
	defer u.Notify()

	return u, nil
}

func (svc *service) RegisterPasskey(username string) (*protocol.CredentialCreation, error) {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return nil, err
	}

	userID := uuid.New()

	return svc.passkeys.InitializeRegistration(userID.String(), u.Username)
}

func (svc *service) Handler() (EventHandler, error) {
	return svc, nil
}

func (svc *service) UserRegisteredHandler(e *user.UserRegisteredEvent) error {
	return svc.users.Store(&e.User)
}

func (svc *service) UserActivatedHandler(e *user.UserActivatedEvent) error {
	u, err := svc.users.Find(e.UserID)
	if err != nil {
		return err
	}

	u.Status = e.Status
	u.UpdatedAt = e.OccuredAt

	return svc.users.Store(u)
}

func (svc *service) UserSocialAccountAddedHandler(e *user.UserSocialAccountAddedEvent) error {
	u, err := svc.users.Find(e.UserID)
	if err != nil {
		return err
	}

	u.Accounts = append(u.Accounts, &e.Account)
	u.UpdatedAt = e.OccuredAt

	return svc.users.Store(u)
}
