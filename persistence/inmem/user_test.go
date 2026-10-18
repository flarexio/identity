package inmem

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/persistence/repotest"
)

func TestUserRepository(t *testing.T) {
	users, err := NewUserRepository()
	if err != nil {
		t.Fatal(err)
	}

	suite.Run(t, &repotest.Suite{Users: users})
}
