// Package token mints and verifies the EdDSA-signed JWTs identity issues.
//
// There are two kinds. Access tokens are bearer tokens for relying parties.
// Session tokens live only in an HttpOnly cookie and can do nothing except
// obtain a fresh access token from identity itself; they are told apart by
// header type and audience, so neither is accepted in place of the other.
//
// Both carry auth_time, the moment the user last really authenticated.
// Nothing issued from it may outlive auth_time + Config.RenewWindow, however
// often it is renewed.
package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"

	"github.com/flarexio/identity/user"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrRenewExpired = errors.New("sign in again")
)

const (
	sessionAudience = "urn:flarexio:identity:session"
	sessionType     = "identity-session+jwt"
	leeway          = 10 * time.Second
)

// Claims are the claims of an access token.
type Claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`

	// The user's ID. Unlike the username in sub it is never reused, so
	// renewal checks it to make sure the account is still the same one.
	UserID string `json:"uid,omitempty"`

	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`

	// Absent when the user has no passkey linked, so that a relying party sees
	// nothing rather than an empty string it might match against.
	PasskeyUserID string `json:"passkey_user_id,omitempty"`
}

// Map is the view of the claims the authorization policy evaluates.
func (c *Claims) Map() map[string]any {
	return map[string]any{
		"sub":   c.Subject,
		"roles": c.Roles,
	}
}

// Token is an issued token as returned to clients.
type Token struct {
	Token     string    `json:"token"`
	ExpiredAt time.Time `json:"expired_at"`
}

type Config struct {
	Issuer    string
	Audiences []string // access tokens are verified against the first
	Key       ed25519.PrivateKey
	Lifetime  time.Duration

	// How long after auth_time tokens may still be issued. Zero means
	// Lifetime: no renewal at all.
	RenewWindow time.Duration

	Admins []string // user IDs granted the "admin" role
}

type Issuer struct {
	cfg Config
	pub ed25519.PublicKey
	kid string
	now func() time.Time
}

func NewIssuer(cfg Config) (*Issuer, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("token: invalid ed25519 key")
	}

	if cfg.Issuer == "" || len(cfg.Audiences) == 0 {
		return nil, errors.New("token: issuer and audience are required")
	}

	if cfg.Lifetime <= 0 {
		return nil, errors.New("token: lifetime must be positive")
	}

	if cfg.RenewWindow < cfg.Lifetime {
		cfg.RenewWindow = cfg.Lifetime
	}

	pub := cfg.Key.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(pub)

	return &Issuer{
		cfg: cfg,
		pub: pub,
		kid: base64.RawURLEncoding.EncodeToString(hash[:16]),
		now: time.Now,
	}, nil
}

func (i *Issuer) Issuer() string { return i.cfg.Issuer }

// Renewable reports whether a session that began at authTime may still be
// renewed.
func (i *Issuer) Renewable(authTime time.Time) bool {
	return i.now().Before(authTime.Add(i.cfg.RenewWindow))
}

// Issue mints an access token for u, who authenticated at authTime.
func (i *Issuer) Issue(u *user.User, authTime time.Time) (*Token, error) {
	now := i.now()

	deadline := authTime.Add(i.cfg.RenewWindow)
	if !now.Before(deadline) {
		return nil, ErrRenewExpired
	}

	exp := now.Add(i.cfg.Lifetime)
	if exp.After(deadline) {
		exp = deadline
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   u.Username,
			Audience:  i.cfg.Audiences,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        ulid.Make().String(),
		},
		Roles:         i.roles(u),
		UserID:        u.ID.String(),
		AuthTime:      jwt.NewNumericDate(authTime),
		PasskeyUserID: passkeyUserID(u),
	}

	signed, err := i.sign(claims, "JWT")
	if err != nil {
		return nil, err
	}

	return &Token{Token: signed, ExpiredAt: exp}, nil
}

// Parse verifies an access token.
func (i *Issuer) Parse(signed string) (*Claims, error) {
	var claims Claims
	if err := i.parse(signed, &claims, i.cfg.Audiences[0], "JWT"); err != nil {
		return nil, err
	}

	return &claims, nil
}

type sessionClaims struct {
	jwt.RegisteredClaims
	AuthTime *jwt.NumericDate `json:"auth_time"`
}

// IssueSession mints the session cookie value for u. It lasts until the
// renew window closes, and names the user by ID so that a username freed
// and taken by someone else does not inherit the session.
func (i *Issuer) IssueSession(u *user.User, authTime time.Time) (*Token, error) {
	now := i.now()

	exp := authTime.Add(i.cfg.RenewWindow)
	if !now.Before(exp) {
		return nil, ErrRenewExpired
	}

	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   u.ID.String(),
			Audience:  jwt.ClaimStrings{sessionAudience},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        ulid.Make().String(),
		},
		AuthTime: jwt.NewNumericDate(authTime),
	}

	signed, err := i.sign(claims, sessionType)
	if err != nil {
		return nil, err
	}

	return &Token{Token: signed, ExpiredAt: exp}, nil
}

// ParseSession verifies a session token and returns whose session it is and
// when they authenticated.
func (i *Issuer) ParseSession(signed string) (user.UserID, time.Time, error) {
	var claims sessionClaims
	if err := i.parse(signed, &claims, sessionAudience, sessionType); err != nil {
		return user.UserID{}, time.Time{}, err
	}

	if claims.AuthTime == nil {
		return user.UserID{}, time.Time{}, ErrInvalidToken
	}

	id, err := user.ParseID(claims.Subject)
	if err != nil {
		return user.UserID{}, time.Time{}, ErrInvalidToken
	}

	return id, claims.AuthTime.Time, nil
}

func (i *Issuer) sign(claims jwt.Claims, typ string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = i.kid
	t.Header["typ"] = typ

	return t.SignedString(i.cfg.Key)
}

func (i *Issuer) parse(signed string, claims jwt.Claims, audience, typ string) error {
	keyFn := func(t *jwt.Token) (any, error) {
		if got, _ := t.Header["typ"].(string); got != typ {
			return nil, fmt.Errorf("unexpected token type %q", got)
		}

		return i.pub, nil
	}

	_, err := jwt.ParseWithClaims(signed, claims, keyFn,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(i.cfg.Issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(i.now),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return nil
}

func (i *Issuer) roles(u *user.User) []string {
	roles := []string{"user"}
	if slices.Contains(i.cfg.Admins, u.ID.String()) {
		roles = append(roles, "admin")
	}
	return roles
}

func passkeyUserID(u *user.User) string {
	id, ok := u.SocialID(user.PASSKEYS)
	if !ok {
		return ""
	}

	return string(id)
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS is the public key set relying parties verify access tokens with.
func (i *Issuer) JWKS() JWKSet {
	return JWKSet{Keys: []JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(i.pub),
		Alg: "EdDSA",
		Use: "sig",
		Kid: i.kid,
	}}}
}
