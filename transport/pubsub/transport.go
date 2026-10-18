package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/nats-io/nats.go/micro"
	"go.uber.org/zap"

	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/eventsig"
	"github.com/flarexio/identity/user"
)

// EventHandler feeds users.> events to the projection. Only events signed
// by a key verifier trusts are applied; with allowUnsigned, events without
// any signature are too (see conf.EventSigning).
//
// Returning an error leaves the message unacknowledged so JetStream
// redelivers it; that is right for a storage hiccup but would loop forever
// on an event that can never apply, so those are logged and acknowledged.
func EventHandler(endpoint endpoint.Endpoint, verifier *eventsig.Verifier, allowUnsigned bool, log *zap.Logger) pubsub.MessageHandler {
	return func(ctx context.Context, msg *pubsub.Message) error {
		payload, err := verifier.Verify(msg.Topic, msg.Data)
		switch {
		case err == nil:
		case errors.Is(err, eventsig.ErrUnsigned) && allowUnsigned:
			log.Warn("applying unsigned event (eventBus.signing.allowUnsigned)", zap.String("topic", msg.Topic))
			payload = msg.Data
		default:
			log.Error("dropping event that is not signed by identity", zap.String("topic", msg.Topic), zap.Error(err))
			return nil
		}

		event, err := decodeEvent(&pubsub.Message{Topic: msg.Topic, Data: payload})
		if err != nil {
			log.Error("dropping undecodable event", zap.String("topic", msg.Topic), zap.Error(err))
			return nil
		}

		_, err = endpoint(ctx, event)
		if permanent(err) {
			log.Error("dropping event that cannot apply", zap.String("topic", msg.Topic), zap.Error(err))
			return nil
		}

		return err
	}
}

func permanent(err error) bool {
	return errors.Is(err, identity.ErrStaleEvent) ||
		errors.Is(err, user.ErrUserNotFound) ||
		errors.Is(err, user.ErrUsernameTaken) ||
		errors.Is(err, user.ErrSocialAccountExists)
}

func decodeEvent(msg *pubsub.Message) (any, error) {
	ss := strings.Split(msg.Topic, ".")
	if len(ss) != 3 || ss[0] != "users" {
		return nil, errors.New("unexpected topic")
	}

	var event any
	switch user.ParseEventName("user_" + ss[2]) {
	case user.UserRegistered:
		event = new(user.UserRegisteredEvent)
	case user.UserActivated:
		event = new(user.UserActivatedEvent)
	case user.UserSocialAccountAdded:
		event = new(user.UserSocialAccountAddedEvent)
	case user.UserSocialAccountRemoved:
		event = new(user.UserSocialAccountRemovedEvent)
	case user.UserDeleted:
		event = new(user.UserDeletedEvent)
	default:
		return nil, errors.New("unknown event")
	}

	if err := json.Unmarshal(msg.Data, event); err != nil {
		return nil, err
	}

	// The topic names the aggregate too; a payload about another user is
	// malformed (or forged) and must not be applied.
	if id := eventUserID(event); id == nil || id.String() != ss[1] {
		return nil, errors.New("event user does not match topic")
	}

	return event, nil
}

func eventUserID(event any) *user.UserID {
	var e *user.Event
	switch ev := event.(type) {
	case *user.UserRegisteredEvent:
		if ev.Event != nil && ev.User.ID != ev.UserID {
			return nil
		}
		e = ev.Event
	case *user.UserActivatedEvent:
		e = ev.Event
	case *user.UserSocialAccountAddedEvent:
		e = ev.Event
	case *user.UserSocialAccountRemovedEvent:
		e = ev.Event
	case *user.UserDeletedEvent:
		e = ev.Event
	}

	if e == nil {
		return nil
	}

	return &e.UserID
}

// SignInHandler serves identity.signin for services on the bus.
func SignInHandler(endpoint endpoint.Endpoint) micro.HandlerFunc {
	return func(r micro.Request) {
		var req identity.SignInRequest
		if err := json.Unmarshal(r.Data(), &req); err != nil {
			r.Error("400", "invalid request", nil)
			return
		}

		resp, err := endpoint(context.Background(), req)
		if err != nil {
			switch {
			case errors.Is(err, identity.ErrProviderNotSupported):
				r.Error("400", "provider not supported", nil)
			case errors.Is(err, identity.ErrInvalidCredential), errors.Is(err, identity.ErrNotRegistered):
				r.Error("401", "invalid credential", nil)
			case errors.Is(err, identity.ErrAccountInactive):
				r.Error("403", "account is not active", nil)
			default:
				r.Error("500", "internal error", nil)
			}
			return
		}

		r.RespondJSON(resp)
	}
}
