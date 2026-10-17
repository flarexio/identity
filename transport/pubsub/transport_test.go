package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity/user"
)

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
	u := user.NewUser("user01", "User 01", "")
	u.Activate()
	data, err := json.Marshal(u.Events()[0])
	require.NoError(t, err)
	msg := &pubsub.Message{Topic: "users." + u.ID.String() + ".activated", Data: data}

	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{nil, false},
		{user.ErrUserNotFound, false},
		{user.ErrSocialAccountExists, false},
		{errors.New("disk on fire"), true},
	} {
		h := EventHandler(func(context.Context, any) (any, error) { return nil, tc.err }, zap.NewNop())
		got := h(context.Background(), msg)
		assert.Equal(t, tc.retry, got != nil, "%v", tc.err)
	}

	h := EventHandler(func(context.Context, any) (any, error) { return nil, nil }, zap.NewNop())
	assert.NoError(t, h(context.Background(), &pubsub.Message{Topic: "users.x.activated", Data: []byte("{")}),
		"a malformed event is dropped, not retried forever")
}
