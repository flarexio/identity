package kv

import (
	"encoding/json"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/persistence/repotest"
	"github.com/flarexio/identity/user"
)

func TestUserRepository(t *testing.T) {
	users, err := NewUserRepository(conf.Persistence{
		Driver: conf.BadgerDB,
		Name:   "identity",
		InMem:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	suite.Run(t, &repotest.Suite{Users: users})
}

// A store written by the old layout, including the stale "social:" key that
// layout left behind after an account was unlinked.
func TestMigrateLegacyLayout(t *testing.T) {
	dir := t.TempDir()

	u := user.NewUser("user01", "User 01", "user01@example.com")
	require.NoError(t, u.AddSocialAccount(user.GOOGLE, "google-1"))
	require.NoError(t, u.AddSocialAccount(user.LINE, "line-1"))

	stale, err := json.Marshal(u)
	require.NoError(t, err)

	require.NoError(t, u.RemoveSocialAccount(user.LINE, "line-1"))

	current, err := json.Marshal(u)
	require.NoError(t, err)

	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	require.NoError(t, err)
	require.NoError(t, db.Update(func(txn *badger.Txn) error {
		txn.Set(u.ID.Bytes(), current)
		txn.Set([]byte("username:user01"), current)
		txn.Set([]byte("social:google-1"), current)
		return txn.Set([]byte("social:line-1"), stale)
	}))
	require.NoError(t, db.Close())

	users, err := NewUserRepository(conf.Persistence{Host: dir, Name: ""})
	require.NoError(t, err)
	defer users.Close()

	found, err := users.FindByUsername("user01")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Len(t, found.Accounts, 1)

	_, err = users.FindBySocialID(user.GOOGLE, "google-1")
	assert.NoError(t, err)

	_, err = users.FindBySocialID(user.LINE, "line-1")
	assert.ErrorIs(t, err, user.ErrUserNotFound, "an unlinked account must not survive the migration")

	all, err := users.ListAll()
	require.NoError(t, err)
	assert.Len(t, all, 1)
}
