package http

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flarexio/identity/user"
)

// Relying parties read it by name, so the name is part of the contract.
func TestPasskeyUserIDClaim(t *testing.T) {
	assert := assert.New(t)

	bs, err := json.Marshal(Claims{Roles: []string{"user"}, PasskeyUserID: "hanko-abc"})
	if !assert.NoError(err) {
		return
	}

	var raw map[string]any
	if !assert.NoError(json.Unmarshal(bs, &raw)) {
		return
	}

	assert.Equal("hanko-abc", raw["passkey_user_id"])

	var back Claims
	if assert.NoError(json.Unmarshal(bs, &back)) {
		assert.Equal("hanko-abc", back.PasskeyUserID)
	}
}

// No passkey linked means no claim, not an empty one.
func TestPasskeyUserIDOmittedWhenAbsent(t *testing.T) {
	assert := assert.New(t)

	bs, err := json.Marshal(Claims{Roles: []string{"user"}})
	if !assert.NoError(err) {
		return
	}

	var raw map[string]any
	if !assert.NoError(json.Unmarshal(bs, &raw)) {
		return
	}

	_, present := raw["passkey_user_id"]
	assert.False(present)
}

func TestPasskeyUserIDFromUser(t *testing.T) {
	assert := assert.New(t)

	u := user.NewUser("user01", "User01", "user01@example.com")
	assert.Equal("", passkeyUserID(u))

	if err := u.AddSocialAccount(user.PASSKEYS, "hanko-abc"); err != nil {
		assert.Fail(err.Error())
		return
	}

	assert.Equal("hanko-abc", passkeyUserID(u))
}
