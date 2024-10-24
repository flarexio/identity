package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/nats-io/nats.go/micro"

	"github.com/flarexio/core/model"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/user"
)

func EventHandler(endpoint endpoint.Endpoint) pubsub.MessageHandler {
	return func(ctx context.Context, msg *pubsub.Message) error {
		ss := strings.Split(msg.Topic, ".")
		if len(ss) != 3 || ss[0] != "users" {
			return errors.New("invalid event")
		}

		name := user.ParseEventName("user_" + ss[2])

		var event any
		switch name {
		case user.UserRegistered:
			var e *user.UserRegisteredEvent
			if err := json.Unmarshal(msg.Data, &e); err != nil {
				return err
			}
			event = e

		case user.UserActivated:
			var e *user.UserActivatedEvent
			if err := json.Unmarshal(msg.Data, &e); err != nil {
				return err
			}
			event = e

		case user.UserSocialAccountAdded:
			var e *user.UserSocialAccountAddedEvent
			if err := json.Unmarshal(msg.Data, &e); err != nil {
				return err
			}
			event = e

		default:
			return errors.New("invalid event")
		}

		_, err := endpoint(ctx, event)
		return err
	}
}

func SignInHandler(endpoint endpoint.Endpoint) micro.HandlerFunc {
	return func(r micro.Request) {
		var req identity.SignInRequest
		if err := json.Unmarshal(r.Data(), &req); err != nil {
			r.Error("400", err.Error(), nil)
			return
		}

		ctx := context.Background()
		resp, err := endpoint(ctx, req)
		if err != nil {
			r.Error("417", err.Error(), nil)
			return
		}

		r.RespondJSON(&resp)
	}
}

func CheckHealthHandler(endpoint endpoint.Endpoint) micro.HandlerFunc {
	return func(r micro.Request) {
		var info *identity.RequestInfo
		if err := json.Unmarshal(r.Data(), &info); err != nil {
			r.Error("400", err.Error(), nil)
			return
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, model.RequestInfo, info)

		_, err := endpoint(ctx, nil)
		if err != nil {
			r.Error("417", err.Error(), nil)
			return
		}
	}
}
