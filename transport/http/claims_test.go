package http

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flarexio/identity/user"
)

// The claim has to survive a round trip through JSON under the name relying
// parties read it by.
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

// A user with no passkey linked gets no claim at all, rather than an empty
// one a relying party might compare against.
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
