package token

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flarexio/identity/user"
)

func newIssuer(t *testing.T, mutate func(*Config)) (*Issuer, *time.Time) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:      "identity.example.com",
		Audiences:   []string{"identity.example.com", "wallet.example.com"},
		Key:         key,
		Lifetime:    time.Hour,
		RenewWindow: 3 * time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	i, err := NewIssuer(cfg)
	require.NoError(t, err)

	now := time.Now().Truncate(time.Second)
	i.now = func() time.Time { return now }
	return i, &now
}

func TestIssueAndParse(t *testing.T) {
	i, now := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")

	tok, err := i.Issue(u, *now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Hour), tok.ExpiredAt)

	claims, err := i.Parse(tok.Token)
	require.NoError(t, err)
	assert.Equal(t, "user01", claims.Subject)
	assert.Equal(t, u.ID.String(), claims.UserID)
	assert.Equal(t, []string{"user"}, claims.Roles)
	assert.Equal(t, now.Unix(), claims.AuthTime.Unix())
}

// However often a token is renewed, nothing outlives auth_time + RenewWindow.
func TestRenewWindowCapsExpiry(t *testing.T) {
	i, now := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")
	authTime := *now

	*now = authTime.Add(150 * time.Minute)
	tok, err := i.Issue(u, authTime)
	require.NoError(t, err)
	assert.Equal(t, authTime.Add(3*time.Hour), tok.ExpiredAt)

	*now = authTime.Add(3 * time.Hour)
	assert.False(t, i.Renewable(authTime))
	_, err = i.Issue(u, authTime)
	assert.ErrorIs(t, err, ErrRenewExpired)
	_, err = i.IssueSession(u, authTime)
	assert.ErrorIs(t, err, ErrRenewExpired)
}

func TestAdminsAreMatchedByID(t *testing.T) {
	admin := user.NewUser("admin", "Admin", "admin@example.com")
	i, now := newIssuer(t, func(c *Config) { c.Admins = []string{admin.ID.String()} })

	tok, err := i.Issue(admin, *now)
	require.NoError(t, err)
	claims, err := i.Parse(tok.Token)
	require.NoError(t, err)
	assert.Equal(t, []string{"user", "admin"}, claims.Roles)

	namesake := user.NewUser("admin", "Someone Else", "admin@elsewhere.example")
	tok, err = i.Issue(namesake, *now)
	require.NoError(t, err)
	claims, err = i.Parse(tok.Token)
	require.NoError(t, err)
	assert.Equal(t, []string{"user"}, claims.Roles, "a username alone must not grant admin")
}

func TestSessionRoundTrip(t *testing.T) {
	i, now := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")

	tok, err := i.IssueSession(u, *now)
	require.NoError(t, err)

	id, authTime, err := i.ParseSession(tok.Token)
	require.NoError(t, err)
	assert.Equal(t, u.ID, id)
	assert.Equal(t, now.Unix(), authTime.Unix())
}

// A session cookie is not a bearer token, nor the other way round.
func TestTokenKindsAreNotInterchangeable(t *testing.T) {
	i, now := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")

	session, err := i.IssueSession(u, *now)
	require.NoError(t, err)
	_, err = i.Parse(session.Token)
	assert.ErrorIs(t, err, ErrInvalidToken)

	access, err := i.Issue(u, *now)
	require.NoError(t, err)
	_, _, err = i.ParseSession(access.Token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestParseRejects(t *testing.T) {
	i, now := newIssuer(t, nil)
	other, _ := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")

	forged, err := other.Issue(u, *now)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": "identity.example.com",
		"aud": "identity.example.com",
		"sub": "user01",
		"exp": now.Add(time.Hour).Unix(),
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	hmac, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(i.pub))
	require.NoError(t, err)

	wrongAudience, err := i.sign(Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    "identity.example.com",
		Audience:  jwt.ClaimStrings{"wallet.example.com"},
		Subject:   "user01",
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}}, "JWT")
	require.NoError(t, err)

	noExpiry, err := i.sign(Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:   "identity.example.com",
		Audience: jwt.ClaimStrings{"identity.example.com"},
		Subject:  "user01",
	}}, "JWT")
	require.NoError(t, err)

	for name, signed := range map[string]string{
		"other key":      forged.Token,
		"alg none":       unsigned,
		"hmac with pub":  hmac,
		"wrong audience": wrongAudience,
		"no expiry":      noExpiry,
		"garbage":        "not.a.token",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := i.Parse(signed)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

// Relying parties read it by name, so the name is part of the contract.
func TestPasskeyUserIDClaim(t *testing.T) {
	bs, err := json.Marshal(Claims{Roles: []string{"user"}, PasskeyUserID: "hanko-abc"})
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(bs, &raw))
	assert.Equal(t, "hanko-abc", raw["passkey_user_id"])
}

// No passkey linked means no claim, not an empty one.
func TestPasskeyUserIDOmittedWhenAbsent(t *testing.T) {
	i, now := newIssuer(t, nil)
	u := user.NewUser("user01", "User 01", "user01@example.com")

	tok, err := i.Issue(u, *now)
	require.NoError(t, err)

	var raw jwt.MapClaims
	_, _, err = jwt.NewParser().ParseUnverified(tok.Token, &raw)
	require.NoError(t, err)
	_, present := raw["passkey_user_id"]
	assert.False(t, present)

	require.NoError(t, u.AddSocialAccount(user.PASSKEYS, "hanko-abc"))
	tok, err = i.Issue(u, *now)
	require.NoError(t, err)

	claims, err := i.Parse(tok.Token)
	require.NoError(t, err)
	assert.Equal(t, "hanko-abc", claims.PasskeyUserID)
}
