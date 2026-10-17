package identity

import (
	"errors"

	"github.com/flarexio/identity/provider"
)

var (
	ErrInvalidCredential    = provider.ErrInvalidCredential
	ErrInvalidArgument      = errors.New("invalid argument")
	ErrProviderNotSupported = errors.New("provider not supported")
	ErrNotRegistered        = errors.New("no account is linked to this credential")
	ErrAccountInactive      = errors.New("account is not active")
	ErrAccountLinked        = errors.New("account already linked to a user")
)
