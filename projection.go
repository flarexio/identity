package identity

import (
	"context"
	"errors"

	"github.com/flarexio/identity/user"
)

// EventHandler projects user events into the repository. Commands only
// publish events; this is where they are written down. JetStream delivers at
// least once, so every handler must be safe to run twice.
//
// An event never applies to a user whose state is newer than the event.
// Besides redeliveries, that stops replays: re-publishing a genuine, signed
// "account linked" event after the account was unlinked changes nothing.
type EventHandler interface {
	UserRegisteredHandler(ctx context.Context, e *user.UserRegisteredEvent) error
	UserActivatedHandler(ctx context.Context, e *user.UserActivatedEvent) error
	UserSocialAccountAddedHandler(ctx context.Context, e *user.UserSocialAccountAddedEvent) error
	UserSocialAccountRemovedHandler(ctx context.Context, e *user.UserSocialAccountRemovedEvent) error
	UserDeletedHandler(ctx context.Context, e *user.UserDeletedEvent) error
}

type EventHandlerMiddleware func(EventHandler) EventHandler

func NewEventHandler(users user.Repository) EventHandler {
	return &projection{users}
}

type projection struct {
	users user.Repository
}

// current loads the user an event applies to, refusing stale events.
func (p *projection) current(e *user.Event) (*user.User, error) {
	u, err := p.users.Find(e.UserID)
	if err != nil {
		return nil, err
	}

	if e.OccuredAt.Before(u.UpdatedAt) {
		return nil, ErrStaleEvent
	}

	return u, nil
}

func (p *projection) UserRegisteredHandler(ctx context.Context, e *user.UserRegisteredEvent) error {
	if _, err := p.users.Find(e.UserID); err == nil {
		return nil // redelivered
	} else if !errors.Is(err, user.ErrUserNotFound) {
		return err
	}

	return p.users.Store(&e.User)
}

func (p *projection) UserActivatedHandler(ctx context.Context, e *user.UserActivatedEvent) error {
	u, err := p.current(e.Event)
	if err != nil {
		return err
	}

	u.Status = e.Status
	u.UpdatedAt = e.OccuredAt

	return p.users.Store(u)
}

func (p *projection) UserSocialAccountAddedHandler(ctx context.Context, e *user.UserSocialAccountAddedEvent) error {
	u, err := p.current(e.Event)
	if err != nil {
		return err
	}

	if u.HasSocialAccount(e.Account.Provider, e.Account.SocialID) {
		return nil
	}

	account := e.Account
	u.Accounts = append(u.Accounts, &account)
	u.UpdatedAt = e.OccuredAt

	return p.users.Store(u)
}

func (p *projection) UserSocialAccountRemovedHandler(ctx context.Context, e *user.UserSocialAccountRemovedEvent) error {
	u, err := p.current(e.Event)
	if err != nil {
		return err
	}

	accounts := make([]*user.SocialAccount, 0, len(u.Accounts))
	for _, a := range u.Accounts {
		if a.Provider == e.Account.Provider && a.SocialID == e.Account.SocialID {
			continue
		}

		accounts = append(accounts, a)
	}

	u.Accounts = accounts
	u.UpdatedAt = e.OccuredAt

	return p.users.Store(u)
}

func (p *projection) UserDeletedHandler(ctx context.Context, e *user.UserDeletedEvent) error {
	u, err := p.current(e.Event)
	if errors.Is(err, user.ErrUserNotFound) {
		return nil // redelivered
	}
	if err != nil {
		return err
	}

	u.Status = user.Revoked
	u.UpdatedAt = e.OccuredAt
	u.DeletedAt = e.OccuredAt

	return p.users.Delete(u)
}
