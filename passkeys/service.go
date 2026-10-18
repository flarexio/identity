package passkeys

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/go-resty/resty/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-jwt/jwt/v5"

	"github.com/flarexio/identity/conf"
)

// ErrRejected means the Passkeys API turned the request down (a failed or
// expired ceremony, say), as opposed to being unreachable.
var ErrRejected = errors.New("passkey ceremony rejected")

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
	VerifySubject(token string) (string, error)
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

// NewService returns nil, nil when no Passkeys API is configured.
func NewService(cfg conf.PasskeysProvider) (Service, error) {
	if cfg.BaseURL == "" {
		return nil, nil
	}

	if cfg.Audience == "" {
		return nil, errors.New("providers.passkeys.audience is required")
	}

	baseURL := cfg.BaseURL + "/" + cfg.TenantID

	client := resty.New().
		SetTimeout(10*time.Second).
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
		return nil, failure(resp, failureResult)
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
		return "", failure(resp, failureResult)
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
		return nil, "", failure(resp, failureResult)
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
		return "", failure(resp, failureResult)
	}

	return successResult.Token, nil
}

func (svc *service) VerifyToken(token string) (*jwt.Token, error) {
	if svc.jwks == nil {
		return nil, errors.New("jwks not found")
	}

	return jwt.Parse(token, svc.jwks,
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"}),
		jwt.WithAudience(svc.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(10*time.Second),
	)
}

func (svc *service) VerifySubject(token string) (string, error) {
	t, err := svc.VerifyToken(token)
	if err != nil {
		return "", err
	}

	subject, err := t.Claims.GetSubject()
	if err != nil {
		return "", err
	}

	if subject == "" {
		return "", errors.New("token has no subject")
	}

	return subject, nil
}

// failure turns a non-200 answer into an error, marking client-side
// failures as ErrRejected so they are not reported as outages.
func failure(resp *resty.Response, result *FailureResult) error {
	var cause error = result
	if result == nil {
		cause = fmt.Errorf("status %d", resp.StatusCode())
	}

	if code := resp.StatusCode(); code >= 400 && code < 500 {
		return fmt.Errorf("%w: %v", ErrRejected, cause)
	}

	return fmt.Errorf("passkeys api: %w", cause)
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
		return nil, "", failure(resp, failureResult)
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
		return "", failure(resp, failureResult)
	}

	return successResult.Token, nil
}
