package kv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/user"
)

// Key layout (schema 1). Each user is stored once; the indexes hold only its
// ID, so dropping an index entry can never leave a stale copy of the user
// that still resolves.
//
//	meta:schema                      -> "1"
//	user:<ulid>                      -> user JSON
//	username:<username>              -> <ulid>
//	social:<provider>:<social id>    -> <ulid>
const schemaVersion = "1"

var (
	schemaKey      = []byte("meta:schema")
	userPrefix     = []byte("user:")
	usernamePrefix = []byte("username:")
	socialPrefix   = []byte("social:")
)

func userKey(id user.UserID) []byte {
	return append(bytes.Clone(userPrefix), id.String()...)
}

func usernameKey(username string) []byte {
	return append(bytes.Clone(usernamePrefix), username...)
}

func socialKey(provider user.SocialProvider, socialID user.SocialID) []byte {
	return []byte(string(socialPrefix) + string(provider) + ":" + string(socialID))
}

func NewUserRepository(cfg conf.Persistence) (user.Repository, error) {
	opts := badger.DefaultOptions(cfg.Host + "/" + cfg.Name).WithLogger(nil)
	if cfg.InMem {
		opts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate badger store: %w", err)
	}

	return &userRepository{db}, nil
}

type userRepository struct {
	db *badger.DB
}

func (repo *userRepository) Store(u *user.User) error {
	bs, err := json.Marshal(u)
	if err != nil {
		return err
	}

	return repo.db.Update(func(txn *badger.Txn) error {
		old, err := get(txn, userKey(u.ID))
		switch {
		case err == nil:
			if err := unindex(txn, old); err != nil {
				return err
			}
		case !errors.Is(err, user.ErrUserNotFound):
			return err
		}

		id := []byte(u.ID.String())

		if err := claim(txn, usernameKey(u.Username), id, user.ErrUsernameTaken); err != nil {
			return err
		}

		for _, a := range u.Accounts {
			if err := claim(txn, socialKey(a.Provider, a.SocialID), id, user.ErrSocialAccountExists); err != nil {
				return err
			}
		}

		return txn.Set(userKey(u.ID), bs)
	})
}

// claim points an index key at id, refusing to take it from another user.
func claim(txn *badger.Txn, key, id []byte, taken error) error {
	item, err := txn.Get(key)
	switch {
	case errors.Is(err, badger.ErrKeyNotFound):
	case err != nil:
		return err
	default:
		owner, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		if !bytes.Equal(owner, id) {
			return taken
		}
	}

	return txn.Set(key, id)
}

func unindex(txn *badger.Txn, u *user.User) error {
	if err := txn.Delete(usernameKey(u.Username)); err != nil {
		return err
	}

	for _, a := range u.Accounts {
		if err := txn.Delete(socialKey(a.Provider, a.SocialID)); err != nil {
			return err
		}
	}

	return nil
}

func (repo *userRepository) Delete(u *user.User) error {
	return repo.db.Update(func(txn *badger.Txn) error {
		old, err := get(txn, userKey(u.ID))
		if err != nil {
			if errors.Is(err, user.ErrUserNotFound) {
				return nil
			}
			return err
		}

		if err := unindex(txn, old); err != nil {
			return err
		}

		return txn.Delete(userKey(u.ID))
	})
}

func (repo *userRepository) ListAll() ([]*user.User, error) {
	users := make([]*user.User, 0)

	err := repo.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek(userPrefix); it.ValidForPrefix(userPrefix); it.Next() {
			u, err := decode(it.Item())
			if err != nil {
				return err
			}

			users = append(users, u)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (repo *userRepository) Find(id user.UserID) (*user.User, error) {
	return repo.find(userKey(id))
}

func (repo *userRepository) FindByUsername(username string) (*user.User, error) {
	return repo.findByIndex(usernameKey(username))
}

func (repo *userRepository) FindBySocialID(provider user.SocialProvider, socialID user.SocialID) (*user.User, error) {
	return repo.findByIndex(socialKey(provider, socialID))
}

func (repo *userRepository) find(key []byte) (*user.User, error) {
	var u *user.User
	err := repo.db.View(func(txn *badger.Txn) error {
		var err error
		u, err = get(txn, key)
		return err
	})

	return u, err
}

func (repo *userRepository) findByIndex(key []byte) (*user.User, error) {
	var u *user.User
	err := repo.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return user.ErrUserNotFound
			}
			return err
		}

		id, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		u, err = get(txn, append(bytes.Clone(userPrefix), id...))
		return err
	})

	return u, err
}

func get(txn *badger.Txn, key []byte) (*user.User, error) {
	item, err := txn.Get(key)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, user.ErrUserNotFound
		}
		return nil, err
	}

	return decode(item)
}

func decode(item *badger.Item) (*user.User, error) {
	var u *user.User
	err := item.Value(func(val []byte) error {
		return json.Unmarshal(val, &u)
	})
	if err != nil {
		return nil, err
	}

	return u.Clone(), nil
}

func (repo *userRepository) Close() error {
	return repo.db.Close()
}

func (repo *userRepository) Truncate() error {
	if err := repo.db.DropAll(); err != nil {
		return err
	}

	return repo.db.Update(func(txn *badger.Txn) error {
		return txn.Set(schemaKey, []byte(schemaVersion))
	})
}

// migrate upgrades a store written before schema 1, where every user was
// stored three times over: under its raw 16-byte ID, under "username:<name>"
// and under "social:<id>". Removing a social account there never removed its
// key, so an unlinked account kept signing in to a stale copy of the user.
// Only the ID-keyed copy is authoritative; the rest is dropped and rebuilt.
func migrate(db *badger.DB) error {
	return db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(schemaKey)
		switch {
		case err == nil:
			v, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			if string(v) != schemaVersion {
				return fmt.Errorf("unknown schema version %q", v)
			}
			return nil

		case !errors.Is(err, badger.ErrKeyNotFound):
			return err
		}

		var (
			legacy [][]byte
			users  []*user.User
		)

		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			legacy = append(legacy, key)

			if len(key) != 16 || bytes.HasPrefix(key, usernamePrefix) || bytes.HasPrefix(key, socialPrefix) {
				continue
			}

			u, err := decode(item)
			if err != nil {
				it.Close()
				return fmt.Errorf("decode legacy user %x: %w", key, err)
			}

			if !bytes.Equal(u.ID.Bytes(), key) {
				continue
			}

			users = append(users, u)
		}
		it.Close()

		for _, key := range legacy {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}

		for _, u := range users {
			bs, err := json.Marshal(u)
			if err != nil {
				return err
			}

			id := []byte(u.ID.String())

			if err := claim(txn, usernameKey(u.Username), id, user.ErrUsernameTaken); err != nil {
				return fmt.Errorf("user %s: %w", u.ID, err)
			}

			for _, a := range u.Accounts {
				if err := claim(txn, socialKey(a.Provider, a.SocialID), id, user.ErrSocialAccountExists); err != nil {
					return fmt.Errorf("user %s: %w", u.ID, err)
				}
			}

			if err := txn.Set(userKey(u.ID), bs); err != nil {
				return err
			}
		}

		return txn.Set(schemaKey, []byte(schemaVersion))
	})
}
