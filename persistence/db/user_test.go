package db

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/persistence/repotest"
)

func TestUserRepository(t *testing.T) {
	users, err := NewUserRepository(conf.Persistence{
		Driver: conf.SQLite,
		Name:   "identity",
		InMem:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	suite.Run(t, &repotest.Suite{Users: users})
}
