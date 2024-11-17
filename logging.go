package identity

import (
	"go.uber.org/zap"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/flarexio/identity/user"
)

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

func (mw *loggingMiddleware) Register(username string, name string, email string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "register"),
		zap.String("username", username),
	)

	u, err := mw.next.Register(username, name, email)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user registered")
	return u, nil
}

func (mw *loggingMiddleware) OTPVerify(otp string, username string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "otp_verify"),
		zap.String("username", username),
	)

	u, err := mw.next.OTPVerify(otp, username)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("success verified")
	return u, nil
}

func (mw *loggingMiddleware) SignIn(credential string, provider user.SocialProvider) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "signin"),
		zap.String("provider", string(provider)),
	)

	u, err := mw.next.SignIn(credential, provider)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user signed in",
		zap.String("user_id", u.ID.String()),
		zap.String("username", u.Username),
	)
	return u, nil
}

func (mw *loggingMiddleware) AddSocialAccount(credential string, provider user.SocialProvider, username string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "add_social_account"),
		zap.String("provider", string(provider)),
		zap.String("username", username),
	)

	u, err := mw.next.AddSocialAccount(credential, provider, username)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user social account added")
	return u, nil
}

func (mw *loggingMiddleware) User(username string) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "user"),
		zap.String("username", username),
	)

	u, err := mw.next.User(username)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user found")
	return u, nil
}

func (mw *loggingMiddleware) RegisterPasskey(username string) (*protocol.CredentialCreation, error) {
	log := mw.log.With(
		zap.String("action", "register_passkey"),
		zap.String("username", username),
	)

	opts, err := mw.next.RegisterPasskey(username)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("passkey registered")
	return opts, nil
}

func (mw *loggingMiddleware) Handler() (EventHandler, error) {
	return mw, nil
}

func (mw *loggingMiddleware) UserRegisteredHandler(e *user.UserRegisteredEvent) error {
	log := mw.log.With(
		zap.String("event", e.EventName()),
		zap.String("user_id", e.UserID.String()),
	)

	handler, err := mw.next.Handler()
	if err != nil {
		return err
	}

	if err := handler.UserRegisteredHandler(e); err != nil {
		log.Error(err.Error())
	}

	log.Info("user stored")
	return nil
}

func (mw *loggingMiddleware) UserActivatedHandler(e *user.UserActivatedEvent) error {
	log := mw.log.With(
		zap.String("event", e.EventName()),
		zap.String("user_id", e.UserID.String()),
	)

	handler, err := mw.next.Handler()
	if err != nil {
		return err
	}

	if err := handler.UserActivatedHandler(e); err != nil {
		log.Error(err.Error())
	}

	log.Info("user activated")
	return nil
}

func (mw *loggingMiddleware) UserSocialAccountAddedHandler(e *user.UserSocialAccountAddedEvent) error {
	log := mw.log.With(
		zap.String("event", e.EventName()),
		zap.String("user_id", e.Event.UserID.String()),
	)

	handler, err := mw.next.Handler()
	if err != nil {
		return err
	}

	if err := handler.UserSocialAccountAddedHandler(e); err != nil {
		log.Error(err.Error())
	}

	log.Info("social account added")
	return nil
}
