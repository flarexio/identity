package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/provider"
	"github.com/flarexio/identity/user"
)

type Service interface {
	SignIn(ctx context.Context, credential string, provider user.SocialProvider) (*user.User, error)
	AddSocialAccount(ctx context.Context, credential string, provider user.SocialProvider, username string) (*user.User, error)
	RemoveSocialAccount(ctx context.Context, provider user.SocialProvider, socialID user.SocialID, username string) (*user.User, error)
	RegisterPasskey(ctx context.Context, username string) (*protocol.CredentialCreation, error)
	User(ctx context.Context, username string) (*user.User, error)

	// ActiveUser loads a user who may be issued tokens, for renewing them.
	ActiveUser(ctx context.Context, id user.UserID) (*user.User, error)

	// UserBySocialID finds the active user linked to socialID. An empty
	// provider searches every provider and fails if the ID is ambiguous.
	UserBySocialID(ctx context.Context, provider user.SocialProvider, socialID user.SocialID) (*user.User, error)

	DeleteUser(ctx context.Context, username string) error
}

type ServiceMiddleware func(Service) Service

// Provider is one way of signing in.
type Provider struct {
	provider.Verifier

	// Whether a first sign-in with an unknown identity opens an account.
	// Passkeys cannot: a passkey is only ever registered to an existing one.
	OpensAccounts bool
}

func NewService(users user.Repository, providers map[user.SocialProvider]Provider, passkeys passkeys.Service) Service {
	return &service{users, providers, passkeys}
}

type service struct {
	users     user.Repository
	providers map[user.SocialProvider]Provider
	passkeys  passkeys.Service
}

func (svc *service) verify(ctx context.Context, credential string, p user.SocialProvider) (*provider.Identity, Provider, error) {
	verifier, ok := svc.providers[p]
	if !ok {
		return nil, Provider{}, ErrProviderNotSupported
	}

	if credential == "" {
		return nil, Provider{}, ErrInvalidCredential
	}

	id, err := verifier.Verify(ctx, credential)
	if err != nil {
		return nil, Provider{}, err
	}

	return id, verifier, nil
}

func (svc *service) SignIn(ctx context.Context, credential string, p user.SocialProvider) (*user.User, error) {
	id, verifier, err := svc.verify(ctx, credential, p)
	if err != nil {
		return nil, err
	}

	socialID := user.SocialID(id.Subject)

	u, err := svc.users.FindBySocialID(p, socialID)
	if err == nil {
		if !u.Active() {
			return nil, ErrAccountInactive
		}

		return u, nil
	}

	if !errors.Is(err, user.ErrUserNotFound) {
		return nil, err
	}

	if !verifier.OpensAccounts {
		return nil, ErrNotRegistered
	}

	username, err := svc.uniqueUsername(id)
	if err != nil {
		return nil, err
	}

	u = user.NewUser(username, id.Name, id.Email)
	u.Avatar = id.Picture

	u.Register()
	u.Activate()
	if err := u.AddSocialAccount(p, socialID); err != nil {
		return nil, err
	}

	// The account exists once these events are published; the repository
	// catches up when the projection consumes them.
	if err := u.Notify(); err != nil {
		return nil, fmt.Errorf("publish events: %w", err)
	}

	return u, nil
}

// uniqueUsername derives a username from the e-mail address's local part,
// adding a random suffix when it is taken.
func (svc *service) uniqueUsername(id *provider.Identity) (string, error) {
	local, _, _ := strings.Cut(id.Email, "@")
	base := sanitizeUsername(local)

	if base != "" {
		_, err := svc.users.FindByUsername(base)
		if errors.Is(err, user.ErrUserNotFound) {
			return base, nil
		}
		if err != nil {
			return "", err
		}
	} else {
		base = "user"
	}

	for range 5 {
		suffix := make([]byte, 4)
		if _, err := rand.Read(suffix); err != nil {
			return "", err
		}

		username := base + "." + hex.EncodeToString(suffix)

		_, err := svc.users.FindByUsername(username)
		if errors.Is(err, user.ErrUserNotFound) {
			return username, nil
		}
		if err != nil {
			return "", err
		}
	}

	return "", errors.New("could not find a free username")
}

const maxUsernameLength = 32

// sanitizeUsername keeps a username safe to put in a URL path and a JWT sub:
// lower-case ASCII letters, digits, '.', '_' and '-'.
func sanitizeUsername(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r > unicode.MaxASCII {
			continue
		}

		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}

		if b.Len() == maxUsernameLength {
			break
		}
	}

	return strings.Trim(b.String(), ".-_")
}

func (svc *service) AddSocialAccount(ctx context.Context, credential string, p user.SocialProvider, username string) (*user.User, error) {
	u, err := svc.activeUserByName(username)
	if err != nil {
		return nil, err
	}

	id, _, err := svc.verify(ctx, credential, p)
	if err != nil {
		return nil, err
	}

	// Identity registers passkeys under the user's own ID (RegisterPasskey),
	// so a passkey token for anyone else is not this user's to link.
	if p == user.PASSKEYS && id.Subject != u.ID.String() {
		return nil, fmt.Errorf("%w: passkey belongs to another user", ErrInvalidCredential)
	}

	socialID := user.SocialID(id.Subject)

	owner, err := svc.users.FindBySocialID(p, socialID)
	switch {
	case err == nil:
		if owner.ID == u.ID {
			return nil, user.ErrSocialAccountExists
		}
		return nil, ErrAccountLinked

	case !errors.Is(err, user.ErrUserNotFound):
		return nil, err
	}

	if err := u.AddSocialAccount(p, socialID); err != nil {
		return nil, err
	}

	if err := u.Notify(); err != nil {
		return nil, fmt.Errorf("publish events: %w", err)
	}

	return u, nil
}

func (svc *service) RemoveSocialAccount(ctx context.Context, p user.SocialProvider, socialID user.SocialID, username string) (*user.User, error) {
	u, err := svc.activeUserByName(username)
	if err != nil {
		return nil, err
	}

	if err := u.RemoveSocialAccount(p, socialID); err != nil {
		return nil, err
	}

	if err := u.Notify(); err != nil {
		return nil, fmt.Errorf("publish events: %w", err)
	}

	return u, nil
}

func (svc *service) RegisterPasskey(ctx context.Context, username string) (*protocol.CredentialCreation, error) {
	if svc.passkeys == nil {
		return nil, ErrProviderNotSupported
	}

	u, err := svc.activeUserByName(username)
	if err != nil {
		return nil, err
	}

	// The user's own ID is the WebAuthn user handle, so every passkey they
	// register is grouped under one user at the Passkeys API, and
	// AddSocialAccount can tell the resulting token is theirs.
	return svc.passkeys.InitializeRegistration(u.ID.String(), u.Username)
}

func (svc *service) User(ctx context.Context, username string) (*user.User, error) {
	return svc.users.FindByUsername(username)
}

func (svc *service) activeUserByName(username string) (*user.User, error) {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return nil, err
	}

	if !u.Active() {
		return nil, ErrAccountInactive
	}

	return u, nil
}

func (svc *service) ActiveUser(ctx context.Context, id user.UserID) (*user.User, error) {
	u, err := svc.users.Find(id)
	if err != nil {
		return nil, err
	}

	if !u.Active() {
		return nil, ErrAccountInactive
	}

	return u, nil
}

func (svc *service) UserBySocialID(ctx context.Context, p user.SocialProvider, socialID user.SocialID) (*user.User, error) {
	if socialID == "" {
		return nil, ErrInvalidArgument
	}

	var u *user.User
	if p != "" {
		found, err := svc.users.FindBySocialID(p, socialID)
		if err != nil {
			return nil, err
		}
		u = found
	} else {
		for _, p := range []user.SocialProvider{user.GOOGLE, user.LINE, user.PASSKEYS} {
			found, err := svc.users.FindBySocialID(p, socialID)
			if errors.Is(err, user.ErrUserNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}

			if u != nil && u.ID != found.ID {
				return nil, fmt.Errorf("%w: social id is linked at several providers; name one", ErrInvalidArgument)
			}
			u = found
		}

		if u == nil {
			return nil, user.ErrUserNotFound
		}
	}

	if !u.Active() {
		return nil, ErrAccountInactive
	}

	return u, nil
}

func (svc *service) DeleteUser(ctx context.Context, username string) error {
	u, err := svc.users.FindByUsername(username)
	if err != nil {
		return err
	}

	u.Delete()

	if err := u.Notify(); err != nil {
		return fmt.Errorf("publish events: %w", err)
	}

	return nil
}
