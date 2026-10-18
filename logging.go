package identity

import (
	"context"

	"github.com/go-webauthn/webauthn/protocol"
	"go.uber.org/zap"

	"github.com/flarexio/identity/user"
)

// LoggingMiddleware logs every call. Credentials are never logged.
func LoggingMiddleware(log *zap.Logger) ServiceMiddleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			log.With(
				zap.String("service", "identity"),
				zap.String("middleware", "logging"),
			),
			next,
		}
	}
}

type loggingMiddleware struct {
	log  *zap.Logger
	next Service
}

func (mw *loggingMiddleware) done(log *zap.Logger, err error, msg string, fields ...zap.Field) {
	if err != nil {
		log.Warn(msg+" failed", zap.Error(err))
		return
	}

	log.Info(msg, fields...)
}

func (mw *loggingMiddleware) SignIn(ctx context.Context, credential string, provider user.SocialProvider) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "signin"),
		zap.String("provider", string(provider)),
	)

	u, err := mw.next.SignIn(ctx, credential, provider)
	if err != nil {
		mw.done(log, err, "sign in")
		return nil, err
	}

	mw.done(log, nil, "user signed in",
		zap.String("user_id", u.ID.String()),
		zap.String("username", u.Username),
	)
	return u, nil
}

func (mw *loggingMiddleware) AddSocialAccount(ctx context.Context, credential string, provider user.SocialProvider, username string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "add_social_account"),
		zap.String("provider", string(provider)),
		zap.String("username", username),
	)

	u, err := mw.next.AddSocialAccount(ctx, credential, provider, username)
	mw.done(log, err, "social account added")
	return u, err
}

func (mw *loggingMiddleware) RemoveSocialAccount(ctx context.Context, provider user.SocialProvider, socialID user.SocialID, username string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "remove_social_account"),
		zap.String("provider", string(provider)),
		zap.String("username", username),
	)

	u, err := mw.next.RemoveSocialAccount(ctx, provider, socialID, username)
	mw.done(log, err, "social account removed")
	return u, err
}

func (mw *loggingMiddleware) RegisterPasskey(ctx context.Context, username string) (*protocol.CredentialCreation, error) {
	log := mw.log.With(
		zap.String("action", "register_passkey"),
		zap.String("username", username),
	)

	opts, err := mw.next.RegisterPasskey(ctx, username)
	mw.done(log, err, "passkey registration started")
	return opts, err
}

func (mw *loggingMiddleware) User(ctx context.Context, username string) (*user.User, error) {
	u, err := mw.next.User(ctx, username)
	if err != nil {
		mw.done(mw.log.With(zap.String("action", "user"), zap.String("username", username)), err, "find user")
	}
	return u, err
}

func (mw *loggingMiddleware) ActiveUser(ctx context.Context, id user.UserID) (*user.User, error) {
	u, err := mw.next.ActiveUser(ctx, id)
	if err != nil {
		mw.done(mw.log.With(zap.String("action", "active_user"), zap.String("user_id", id.String())), err, "find user")
	}
	return u, err
}

func (mw *loggingMiddleware) UserBySocialID(ctx context.Context, provider user.SocialProvider, socialID user.SocialID) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "user_by_social_id"),
		zap.String("provider", string(provider)),
	)

	u, err := mw.next.UserBySocialID(ctx, provider, socialID)
	if err != nil {
		mw.done(log, err, "find user")
		return nil, err
	}

	mw.done(log, nil, "user found", zap.String("username", u.Username))
	return u, nil
}

func (mw *loggingMiddleware) DeleteUser(ctx context.Context, username string) error {
	log := mw.log.With(
		zap.String("action", "delete_user"),
		zap.String("username", username),
	)

	err := mw.next.DeleteUser(ctx, username)
	mw.done(log, err, "user deleted")
	return err
}

// EventLoggingMiddleware logs projected events, passing errors through so
// the transport can decide whether the event is retried.
func EventLoggingMiddleware(log *zap.Logger) EventHandlerMiddleware {
	return func(next EventHandler) EventHandler {
		return &eventLoggingMiddleware{
			log.With(
				zap.String("service", "identity"),
				zap.String("middleware", "event_logging"),
			),
			next,
		}
	}
}

type eventLoggingMiddleware struct {
	log  *zap.Logger
	next EventHandler
}

func (mw *eventLoggingMiddleware) done(e *user.Event, err error) error {
	log := mw.log.With(
		zap.String("event", e.EventName()),
		zap.String("user_id", e.UserID.String()),
	)

	if err != nil {
		log.Error("event not projected", zap.Error(err))
		return err
	}

	log.Info("event projected")
	return nil
}

func (mw *eventLoggingMiddleware) UserRegisteredHandler(ctx context.Context, e *user.UserRegisteredEvent) error {
	return mw.done(e.Event, mw.next.UserRegisteredHandler(ctx, e))
}

func (mw *eventLoggingMiddleware) UserActivatedHandler(ctx context.Context, e *user.UserActivatedEvent) error {
	return mw.done(e.Event, mw.next.UserActivatedHandler(ctx, e))
}

func (mw *eventLoggingMiddleware) UserSocialAccountAddedHandler(ctx context.Context, e *user.UserSocialAccountAddedEvent) error {
	return mw.done(e.Event, mw.next.UserSocialAccountAddedHandler(ctx, e))
}

func (mw *eventLoggingMiddleware) UserSocialAccountRemovedHandler(ctx context.Context, e *user.UserSocialAccountRemovedEvent) error {
	return mw.done(e.Event, mw.next.UserSocialAccountRemovedHandler(ctx, e))
}

func (mw *eventLoggingMiddleware) UserDeletedHandler(ctx context.Context, e *user.UserDeletedEvent) error {
	return mw.done(e.Event, mw.next.UserDeletedHandler(ctx, e))
}
