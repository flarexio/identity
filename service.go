package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/user"
	"github.com/go-resty/resty/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

var (
	ErrProviderNotSupported = errors.New("provider not supported")
	ErrClientIDNotFound     = errors.New("client id not found")
	ErrEmailNotFound        = errors.New("email not found")
	ErrNameNotFound         = errors.New("name not found")
	ErrPictureNotFound      = errors.New("picture not found")
)

type Service interface {
	Register(username string, name string, email string) (*user.User, error)
	OTPVerify(otp string, id user.UserID) (*user.User, error)
	SignIn(credential string, provider user.SocialProvider) (*user.User, error)
	AddSocialAccount(credential string, provider user.SocialProvider, id user.UserID) (*user.User, error)
	Handler() (EventHandler, error)

	passkeys.PasskeyService
}

type EventHandler interface {
	UserRegisteredHandler(e *user.UserRegisteredEvent) error
	UserActivatedHandler(e *user.UserActivatedEvent) error
	UserSocialAccountAddedHandler(e *user.UserSocialAccountAddedEvent) error
}

type ServiceMiddleware func(Service) Service

type service struct {
	users     user.Repository
	clientIDs map[user.SocialProvider]string
	client    *resty.Client
}

func NewService(users user.Repository, cfg conf.Providers) Service {
	passkeys := cfg.Passkeys

	client := resty.New().
		SetHeader("Content-Type", "application/json").
		SetHeader("apiKey", passkeys.PasskeysAPI.Secret).
		SetBaseURL(passkeys.BaseURL + "/" + passkeys.TenantID)

	return &service{
		users: users,
		clientIDs: map[user.SocialProvider]string{
			user.GOOGLE: cfg.Google.Client.ID,
		},
		client: client,
	}
}

func (svc *service) Handler() (EventHandler, error) {
	return svc, nil
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

func (svc *service) OTPVerify(otp string, id user.UserID) (*user.User, error) {
	u, err := svc.users.Find(id)
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
	}

	return nil, ErrProviderNotSupported
}

func (svc *service) signInWithGoogle(token string) (*user.User, error) {
	clientID, ok := svc.clientIDs[user.GOOGLE]
	if !ok {
		return nil, ErrClientIDNotFound
	}

	payload, err := idtoken.Validate(context.Background(), token, clientID)
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
		u.Activate()
		u.AddSocialAccount(user.GOOGLE, socialID)

		defer u.Notify()
	}

	picture, ok := payload.Claims["picture"].(string)
	if ok {
		u.Avatar = picture
	}

	return u, nil
}

func (svc *service) AddSocialAccount(credential string, provider user.SocialProvider, id user.UserID) (*user.User, error) {
	u, err := svc.users.Find(id)
	if err != nil {
		return nil, err
	}

	clientID, ok := svc.clientIDs[user.GOOGLE]
	if !ok {
		return nil, ErrClientIDNotFound
	}

	payload, err := idtoken.Validate(context.Background(), credential, clientID)
	if err != nil {
		return nil, err
	}

	socialID := user.SocialID(payload.Subject)
	_, err = svc.users.FindBySocialID(socialID)
	if err == nil {
		return nil, errors.New("account exists")
	}

	u.AddSocialAccount(provider, socialID)
	defer u.Notify()

	return u, nil
}

func (svc *service) UserRegisteredHandler(e *user.UserRegisteredEvent) error {
	return svc.users.Store(e.User)
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

	u.Accounts = append(u.Accounts, e.Account)
	u.UpdatedAt = e.OccuredAt

	return svc.users.Store(u)
}

func (svc *service) InitializeRegistration(userID string, username string) (*protocol.CredentialCreation, error) {
	params := map[string]string{
		"user_id":  userID,
		"username": username,
	}

	var (
		successResult *protocol.CredentialCreation
		failureResult *passkeys.FailureResult
	)

	resp, err := svc.client.R().
		SetBody(params).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/registration/initialize")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, failureResult
	}

	return successResult, nil
}

func (svc *service) FinalizeRegistration(req *protocol.ParsedCredentialCreationData) (string, error) {
	var (
		successResult *passkeys.TokenResult
		failureResult *passkeys.FailureResult
	)

	resp, err := svc.client.R().
		SetBody(&req.Raw).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/registration/finalize")

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", failureResult
	}

	return successResult.Token, nil
}

func (svc *service) InitializeLogin(userID string) (*protocol.CredentialAssertion, string, error) {
	params := map[string]string{
		"user_id": userID,
	}

	var (
		successResult *protocol.CredentialAssertion
		failureResult *passkeys.FailureResult
	)

	resp, err := svc.client.R().
		SetBody(params).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/login/initialize")

	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, "", failureResult
	}

	return successResult, "optional", nil
}

func (svc *service) FinalizeLogin(req *protocol.ParsedCredentialAssertionData) (string, error) {
	var (
		successResult *passkeys.TokenResult
		failureResult *passkeys.FailureResult
	)

	resp, err := svc.client.R().
		SetBody(&req.Raw).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/login/finalize")

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", failureResult
	}

	return successResult.Token, nil
}
