package pubsub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/eventsig"
	"github.com/flarexio/identity/user"
)

func signing(t *testing.T) (*eventsig.Signer, *eventsig.Verifier) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return eventsig.NewSigner(priv), eventsig.NewVerifier(pub)
}

func TestDecodeEventChecksTopicAgainstPayload(t *testing.T) {
	u := user.NewUser("user01", "User 01", "")
	u.Register()

	data, err := json.Marshal(u.Events()[0])
	require.NoError(t, err)

	event, err := decodeEvent(&pubsub.Message{Topic: "users." + u.ID.String() + ".registered", Data: data})
	require.NoError(t, err)
	assert.Equal(t, u.ID, event.(*user.UserRegisteredEvent).User.ID)

	other := user.MakeID()
	_, err = decodeEvent(&pubsub.Message{Topic: "users." + other.String() + ".registered", Data: data})
	assert.Error(t, err)

	_, err = decodeEvent(&pubsub.Message{Topic: "users." + u.ID.String() + ".promoted", Data: data})
	assert.Error(t, err)
}

func TestEventHandlerRetriesOnlyTransientErrors(t *testing.T) {
	signer, verifier := signing(t)

	u := user.NewUser("user01", "User 01", "")
	u.Activate()
	topic := "users." + u.ID.String() + ".activated"
	data, err := json.Marshal(u.Events()[0])
	require.NoError(t, err)
	signed, err := signer.Sign(topic, data)
	require.NoError(t, err)
	msg := &pubsub.Message{Topic: topic, Data: signed}

	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{nil, false},
		{user.ErrUserNotFound, false},
		{user.ErrSocialAccountExists, false},
		{identity.ErrStaleEvent, false},
		{errors.New("disk on fire"), true},
	} {
		h := EventHandler(func(context.Context, any) (any, error) { return nil, tc.err }, verifier, false, zap.NewNop())
		got := h(context.Background(), msg)
		assert.Equal(t, tc.retry, got != nil, "%v", tc.err)
	}

	h := EventHandler(func(context.Context, any) (any, error) { return nil, nil }, verifier, false, zap.NewNop())
	assert.NoError(t, h(context.Background(), &pubsub.Message{Topic: "users.x.activated", Data: []byte("{")}),
		"a malformed event is dropped, not retried forever")
}

func TestEventHandlerAppliesOnlySignedEvents(t *testing.T) {
	signer, verifier := signing(t)
	other, _ := signing(t)

	u := user.NewUser("user01", "User 01", "")
	u.Activate()
	topic := "users." + u.ID.String() + ".activated"
	data, err := json.Marshal(u.Events()[0])
	require.NoError(t, err)

	signed, err := signer.Sign(topic, data)
	require.NoError(t, err)
	forged, err := other.Sign(topic, data)
	require.NoError(t, err)

	run := func(data []byte, allowUnsigned bool) bool {
		applied := false
		h := EventHandler(func(_ context.Context, e any) (any, error) {
			applied = true
			assert.Equal(t, u.ID, e.(*user.UserActivatedEvent).UserID)
			return nil, nil
		}, verifier, allowUnsigned, zap.NewNop())

		require.NoError(t, h(context.Background(), &pubsub.Message{Topic: topic, Data: data}))
		return applied
	}

	assert.True(t, run(signed, false))
	assert.False(t, run(data, false), "unsigned")
	assert.False(t, run(forged, false), "signed by another key")
	assert.False(t, run(forged, true), "allowUnsigned does not admit bad signatures")
	assert.True(t, run(data, true), "allowUnsigned admits unsigned history")
}
