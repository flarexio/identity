package eventsig

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return pub, priv
}

const topic = "users.01J0000000000000000000000.social_account_added"

var payload = []byte(`{"name":"user_social_account_added","account":{"social_id":"g-1"}}`)

func TestRoundTrip(t *testing.T) {
	pub, priv := keys(t)

	signed, err := NewSigner(priv).Sign(topic, payload)
	require.NoError(t, err)

	// Consumers that do not verify still see the event, plus one field.
	var event map[string]any
	require.NoError(t, json.Unmarshal(signed, &event))
	assert.Equal(t, "user_social_account_added", event["name"])
	assert.Contains(t, event, "sig")

	got, err := NewVerifier(pub).Verify(topic, signed)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestRotation(t *testing.T) {
	oldPub, oldPriv := keys(t)
	newPub, _ := keys(t)

	signed, err := NewSigner(oldPriv).Sign(topic, payload)
	require.NoError(t, err)

	_, err = NewVerifier(newPub).Verify(topic, signed)
	assert.ErrorIs(t, err, ErrBadSignature)

	_, err = NewVerifier(newPub, oldPub).Verify(topic, signed)
	assert.NoError(t, err)
}

func TestRejects(t *testing.T) {
	pub, priv := keys(t)
	_, otherPriv := keys(t)

	signed, err := NewSigner(priv).Sign(topic, payload)
	require.NoError(t, err)

	forged, err := NewSigner(otherPriv).Sign(topic, payload)
	require.NoError(t, err)

	tampered := []byte(strings.Replace(string(signed), "g-1", "g-2", 1))

	v := NewVerifier(pub)

	for name, tc := range map[string]struct {
		topic string
		data  []byte
		err   error
	}{
		"unsigned":      {topic, payload, ErrUnsigned},
		"other key":     {topic, forged, ErrBadSignature},
		"tampered":      {topic, tampered, ErrBadSignature},
		"other subject": {"users.01J0000000000000000000001.social_account_added", signed, ErrBadSignature},
		"garbage sig":   {topic, []byte(`{"a":1,"sig":"!!"}`), ErrUnsigned},
		"empty":         {topic, nil, ErrUnsigned},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(tc.topic, tc.data)
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

func TestSignRequiresObject(t *testing.T) {
	_, priv := keys(t)

	_, err := NewSigner(priv).Sign(topic, []byte(`[1,2]`))
	assert.ErrorIs(t, err, ErrNotObject)
}
