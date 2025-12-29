package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-jwt/jwt/v5"
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
	SignIn(ctx context.Context, credential string, provider user.SocialProvider) (*user.User, error)
	AddSocialAccount(credential string, provider user.SocialProvider, username string) (*user.User, error)
	RegisterPasskey(username string) (*protocol.CredentialCreation, error)
	User(username string) (*user.User, error)
	UserBySocialID(socialID user.SocialID) (*user.User, error)
	DeleteUser(username string) error
	Handler() (EventHandler, error)
}

type EventHandler interface {
	UserRegisteredHandler(e *user.UserRegisteredEvent) error
	UserActivatedHandler(e *user.UserActivatedEvent) error
	UserSocialAccountAddedHandler(e *user.UserSocialAccountAddedEvent) error
	UserDeletedHandler(e *user.UserDeletedEvent) error
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
	// Ensure username is unique
	_, err := svc.users.FindByUsername(username)
	if err == nil {
		return nil, errors.New("user exists")
	}

	if !errors.Is(err, user.ErrUserNotFound) {
		return nil, err
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

func (svc *service) SignIn(ctx context.Context, credential string, provider user.SocialProvider) (*user.User, error) {
	switch provider {
	case user.GOOGLE:
		return svc.signInWithGoogle(ctx, credential)

	case user.LINE:
		return svc.signInWithLINE(ctx, credential)

	case user.PASSKEYS:
		return svc.signInWithPasskeys(credential)

	default:
		return nil, ErrProviderNotSupported
	}
}

func (svc *service) signInWithGoogle(ctx context.Context, token string) (*user.User, error) {
	audience := svc.cfg.Google.Client.ID
	if audience == "" {
		return nil, ErrAudienceNotFound
	}

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

		// Ensure username is unique
		_, err := svc.users.FindByUsername(username)
		if err == nil {
			username = username + "." + uuid.NewString()[:8]
		} else if !errors.Is(err, user.ErrUserNotFound) {
			return nil, err
		}

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

type LINEClaims struct {
	jwt.RegisteredClaims
	Nonce   string `json:"nonce"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Email   string `json:"email"`
}

func (svc *service) signInWithLINE(ctx context.Context, token string) (*user.User, error) {
	cfg := svc.cfg.LINE

	audience := cfg.Channel.ID
	if audience == "" {
		return nil, ErrAudienceNotFound
	}

	keyFn := func(t *jwt.Token) (any, error) {
		secret := []byte(cfg.Channel.Secret)
		return secret, nil
	}

	var claims LINEClaims
	if _, err := jwt.ParseWithClaims(token, &claims, keyFn,
		jwt.WithIssuer("https://access.line.me"),
		jwt.WithAudience(audience),
		jwt.WithLeeway(10*time.Second),
	); err != nil {
		return nil, err
	}

	nonce, ok := ctx.Value(user.Nonce).(string)
	if !ok || (nonce != claims.Nonce) {
		return nil, errors.New("invalid nonce")
	}

	socialID := user.SocialID(claims.Subject)

	u, err := svc.users.FindBySocialID(socialID)
	if err != nil {
		if !errors.Is(err, user.ErrUserNotFound) {
			return nil, err
		}

		username := strings.Split(claims.Email, "@")[0]

		// Ensure username is unique
		_, err := svc.users.FindByUsername(username)
		if err == nil {
			username = username + "." + uuid.NewString()[:8]
		} else if !errors.Is(err, user.ErrUserNotFound) {
			return nil, err
		}

		u = user.NewUser(username, claims.Name, claims.Email)
		u.Avatar = claims.Picture

		u.Register()
		u.Activate()
		u.AddSocialAccount(user.LINE, socialID)

		defer u.Notify()
	}

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

	case user.LINE:
		cfg := svc.cfg.LINE

		audience := cfg.Channel.ID
		if audience == "" {
			return nil, ErrAudienceNotFound
		}

		keyFn := func(t *jwt.Token) (any, error) {
			secret := []byte(cfg.Channel.Secret)
			return secret, nil
		}

		var claims LINEClaims
		if _, err := jwt.ParseWithClaims(credential, &claims, keyFn,
			jwt.WithIssuer("https://access.line.me"),
			jwt.WithAudience(audience),
			jwt.WithLeeway(10*time.Second),
		); err != nil {
			return nil, err
		}

		subject = claims.Subject

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

func (svc *service) User(username string) (*user.User, error) {
	return svc.users.FindByUsername(username)
}

func (svc *service) UserBySocialID(socialID user.SocialID) (*user.User, error) {
	return svc.users.FindBySocialID(socialID)
}

func (svc *service) DeleteUser(username string) error {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return err
	}

	u.Delete()
	defer u.Notify()

	return nil
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

func (svc *service) UserDeletedHandler(e *user.UserDeletedEvent) error {
	u, err := svc.users.Find(e.UserID)
	if err != nil {
		return err
	}

	u.Status = user.Revoked
	u.UpdatedAt = e.OccuredAt
	u.DeletedAt = e.OccuredAt

	return svc.users.Delete(u)
}
