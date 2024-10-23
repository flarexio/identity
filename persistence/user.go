package persistence

import (
	"errors"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/persistence/db"
	"github.com/flarexio/identity/persistence/inmem"
	"github.com/flarexio/identity/persistence/kv"
	"github.com/flarexio/identity/user"
)

func NewUserRepository(cfg conf.Persistence) (user.Repository, error) {
	switch cfg.Driver {
	case conf.SQLite:
		return db.NewUserRepository(cfg)
	case conf.BadgerDB:
		return kv.NewUserRepository(cfg)
	case conf.InMem:
		return inmem.NewUserRepository()
	default:
		return nil, errors.New("driver not supported")
	}
}
