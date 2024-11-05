package passkeys

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/go-resty/resty/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-jwt/jwt/v5"

	"github.com/flarexio/identity/conf"
)

type Service interface {
	PasskeyService
}

type PasskeyService interface {
	RegistrationService
	LoginService
	// CredentialServie
	TransactionService
}

type RegistrationService interface {
	InitializeRegistration(userID string, username string) (*protocol.CredentialCreation, error)
	FinalizeRegistration(req *protocol.ParsedCredentialCreationData) (string, error)
}

type LoginService interface {
	InitializeLogin(userID string) (*protocol.CredentialAssertion, string, error)
	FinalizeLogin(req *protocol.ParsedCredentialAssertionData) (string, error)
	VerifyToken(token string) (*jwt.Token, error)
}

type CredentialServie interface {
	ListCredentials(userID string) ([]*Credential, error)
	UpdateCredential(credentialID string, name string) error
	RemoveCredential(credentialID string) error
}

type TransactionService interface {
	InitializeTransaction(req *InitializeTransactionRequest) (*protocol.CredentialAssertion, string, error)
	FinalizeTransaction(req *protocol.ParsedCredentialAssertionData) (string, error)
}

func NewService(cfg conf.PasskeysProvider) (Service, error) {
	baseURL := cfg.BaseURL + "/" + cfg.TenantID

	client := resty.New().
		SetHeader("Content-Type", "application/json").
		SetHeader("apiKey", cfg.PasskeysAPI.Secret).
		SetBaseURL(baseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 3000*time.Millisecond)
	defer cancel()

	jwksURL := baseURL + "/.well-known/jwks.json"

	k, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, err
	}

	return &service{
		cfg:    cfg,
		client: client,
		jwks:   k.Keyfunc,
	}, nil
}

type service struct {
	cfg    conf.PasskeysProvider
	client *resty.Client
	jwks   jwt.Keyfunc
}

func (svc *service) InitializeRegistration(userID string, username string) (*protocol.CredentialCreation, error) {
	params := map[string]string{
		"user_id":  userID,
		"username": username,
	}

	var (
		successResult *protocol.CredentialCreation
		failureResult *FailureResult
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
		successResult *TokenResult
		failureResult *FailureResult
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
		failureResult *FailureResult
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
		successResult *TokenResult
		failureResult *FailureResult
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

func (svc *service) VerifyToken(token string) (*jwt.Token, error) {
	if svc.jwks == nil {
		return nil, errors.New("jwks not found")
	}

	return jwt.Parse(token, svc.jwks,
		jwt.WithAudience(svc.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
}

func (svc *service) InitializeTransaction(req *InitializeTransactionRequest) (*protocol.CredentialAssertion, string, error) {
	var (
		successResult *protocol.CredentialAssertion
		failureResult *FailureResult
	)

	resp, err := svc.client.R().
		SetBody(req).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/transaction/initialize")

	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, "", failureResult
	}

	return successResult, "optional", nil
}

func (svc *service) FinalizeTransaction(req *protocol.ParsedCredentialAssertionData) (string, error) {
	var (
		successResult *TokenResult
		failureResult *FailureResult
	)

	resp, err := svc.client.R().
		SetBody(&req.Raw).
		SetResult(&successResult).
		SetError(&failureResult).
		Post("/transaction/finalize")

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", failureResult
	}

	return successResult.Token, nil
}
