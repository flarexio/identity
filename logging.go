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
	)

	u, err := mw.next.Register(username, name, email)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user registered", zap.String("username", u.Username))
	return u, nil
}

func (mw *loggingMiddleware) OTPVerify(otp string, id user.UserID) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "otp_verify"),
		zap.String("user_id", id.String()),
	)

	u, err := mw.next.OTPVerify(otp, id)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("success verified", zap.String("username", u.Username))
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

func (mw *loggingMiddleware) AddSocialAccount(credential string, provider user.SocialProvider, id user.UserID) (*user.User, error) {
	log := mw.log.With(
		zap.String("action", "add_social_account"),
		zap.String("provider", string(provider)),
		zap.String("user_id", id.String()),
	)

	u, err := mw.next.AddSocialAccount(credential, provider, id)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Info("user social account added",
		zap.String("username", u.Username),
	)
	return u, nil
}

func (mw *loggingMiddleware) RegisterPasskey(id user.UserID) (*protocol.CredentialCreation, error) {
	log := mw.log.With(
		zap.String("action", "register_passkey"),
		zap.String("user_id", id.String()),
	)

	opts, err := mw.next.RegisterPasskey(id)
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
