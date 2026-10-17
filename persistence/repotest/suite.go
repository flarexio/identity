// Package repotest is the behaviour every user.Repository backend must share.
package repotest

import (
	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/user"
)

const googleID user.SocialID = "100043685676652067799"

type Suite struct {
	suite.Suite
	Users user.Repository
	user  *user.User
}

func (s *Suite) SetupTest() {
	s.Require().NoError(s.Users.Truncate())

	u := user.NewUser("user01", "User 01", "user01@example.com")
	s.Require().NoError(u.AddSocialAccount(user.GOOGLE, googleID))
	s.Require().NoError(s.Users.Store(u))

	s.user = u
}

func (s *Suite) TearDownSuite() {
	s.Users.Truncate()
	s.Users.Close()
}

func (s *Suite) TestFind() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Equal("user01", u.Username)
	s.Len(u.Accounts, 1)
}

func (s *Suite) TestFindByUsername() {
	u, err := s.Users.FindByUsername("user01")
	s.Require().NoError(err)
	s.Equal(s.user.ID, u.ID)

	_, err = s.Users.FindByUsername("nobody")
	s.ErrorIs(err, user.ErrUserNotFound)
}

func (s *Suite) TestFindBySocialID() {
	u, err := s.Users.FindBySocialID(user.GOOGLE, googleID)
	s.Require().NoError(err)
	s.Equal(s.user.ID, u.ID)
}

// The same ID at another provider is a different account.
func (s *Suite) TestFindBySocialIDIsScopedToProvider() {
	_, err := s.Users.FindBySocialID(user.LINE, googleID)
	s.ErrorIs(err, user.ErrUserNotFound)
}

func (s *Suite) TestAddSocialAccounts() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)

	s.Require().NoError(u.AddSocialAccount(user.LINE, "line-user-123"))
	s.Require().NoError(u.AddSocialAccount(user.PASSKEYS, "passkey-456"))
	s.Require().NoError(s.Users.Store(u))

	found, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Len(found.Accounts, 3)

	byLINE, err := s.Users.FindBySocialID(user.LINE, "line-user-123")
	s.Require().NoError(err)
	s.Equal(s.user.ID, byLINE.ID)
	s.Len(byLINE.Accounts, 3)
}

// An unlinked account must stop resolving to the user.
func (s *Suite) TestRemoveSocialAccount() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Require().NoError(u.AddSocialAccount(user.LINE, "line-user-123"))
	s.Require().NoError(s.Users.Store(u))

	u, err = s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Require().NoError(u.RemoveSocialAccount(user.LINE, "line-user-123"))
	s.Require().NoError(s.Users.Store(u))

	found, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Len(found.Accounts, 1)
	s.Equal(user.GOOGLE, found.Accounts[0].Provider)

	_, err = s.Users.FindBySocialID(user.LINE, "line-user-123")
	s.ErrorIs(err, user.ErrUserNotFound)

	byGoogle, err := s.Users.FindBySocialID(user.GOOGLE, googleID)
	s.Require().NoError(err)
	s.Len(byGoogle.Accounts, 1, "index must resolve to the current user, not a stale copy")
}

func (s *Suite) TestRenameFreesOldUsername() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)

	u.Username = "user01-renamed"
	s.Require().NoError(s.Users.Store(u))

	_, err = s.Users.FindByUsername("user01")
	s.ErrorIs(err, user.ErrUserNotFound)

	found, err := s.Users.FindByUsername("user01-renamed")
	s.Require().NoError(err)
	s.Equal(s.user.ID, found.ID)
}

func (s *Suite) TestUsernameConflict() {
	other := user.NewUser("user01", "Impostor", "impostor@example.com")
	s.ErrorIs(s.Users.Store(other), user.ErrUsernameTaken)

	found, err := s.Users.FindByUsername("user01")
	s.Require().NoError(err)
	s.Equal(s.user.ID, found.ID)
}

func (s *Suite) TestSocialAccountConflict() {
	other := user.NewUser("user02", "Impostor", "impostor@example.com")
	s.Require().NoError(other.AddSocialAccount(user.GOOGLE, googleID))
	s.ErrorIs(s.Users.Store(other), user.ErrSocialAccountExists)

	found, err := s.Users.FindBySocialID(user.GOOGLE, googleID)
	s.Require().NoError(err)
	s.Equal(s.user.ID, found.ID)
}

func (s *Suite) TestDelete() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)

	u.Delete()
	s.Require().NoError(s.Users.Delete(u))

	_, err = s.Users.Find(s.user.ID)
	s.ErrorIs(err, user.ErrUserNotFound)

	_, err = s.Users.FindByUsername("user01")
	s.ErrorIs(err, user.ErrUserNotFound)

	_, err = s.Users.FindBySocialID(user.GOOGLE, googleID)
	s.ErrorIs(err, user.ErrUserNotFound)
}

func (s *Suite) TestListAll() {
	u2 := user.NewUser("user02", "User 02", "user02@example.com")
	s.Require().NoError(u2.AddSocialAccount(user.LINE, "line-user-2"))
	s.Require().NoError(s.Users.Store(u2))

	all, err := s.Users.ListAll()
	s.Require().NoError(err)
	s.Len(all, 2)

	u2.Delete()
	s.Require().NoError(s.Users.Delete(u2))

	all, err = s.Users.ListAll()
	s.Require().NoError(err)
	s.Len(all, 1)
}

// Mutating a user that came out of the repository must not reach the store.
func (s *Suite) TestReturnedUsersAreCopies() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)

	u.Name = "changed"
	u.Accounts[0].SocialID = "changed"

	found, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Equal("User 01", found.Name)
	s.Equal(googleID, found.Accounts[0].SocialID)
}

func (s *Suite) TestAvatarRoundTrip() {
	u, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)

	u.Avatar = "https://example.com/a.png"
	s.Require().NoError(s.Users.Store(u))

	found, err := s.Users.Find(s.user.ID)
	s.Require().NoError(err)
	s.Equal("https://example.com/a.png", found.Avatar)
}
