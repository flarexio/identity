package user

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	assert := assert.New(t)

	u := NewUser("user01", "User01", "user01@example.com")
	u.Register()

	assert.Equal("user01", u.Username)
	assert.Equal("user01@example.com", u.Email)
	assert.Equal(Registered, u.Status)

	jsonStr, err := json.MarshalIndent(u.Events(), "", "    ")
	if err != nil {
		assert.Fail(err.Error())
		return
	}

	fmt.Println(string(jsonStr))
}

func TestSocialID(t *testing.T) {
	assert := assert.New(t)

	u := NewUser("user01", "User01", "user01@example.com")

	_, ok := u.SocialID(PASSKEYS)
	assert.False(ok, "a user with no linked accounts has no passkey id")

	if err := u.AddSocialAccount(GOOGLE, "google-123"); err != nil {
		assert.Fail(err.Error())
		return
	}

	_, ok = u.SocialID(PASSKEYS)
	assert.False(ok, "another provider must not answer for passkeys")

	if err := u.AddSocialAccount(PASSKEYS, "hanko-abc"); err != nil {
		assert.Fail(err.Error())
		return
	}

	id, ok := u.SocialID(PASSKEYS)
	if assert.True(ok) {
		assert.Equal(SocialID("hanko-abc"), id)
	}

	google, ok := u.SocialID(GOOGLE)
	if assert.True(ok) {
		assert.Equal(SocialID("google-123"), google)
	}
}
