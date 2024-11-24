package main

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/persistence"
	"github.com/flarexio/identity/user"
)

type identityTestSuite struct {
	suite.Suite
	cfg   conf.Config
	svc   identity.Service
	users user.Repository
}

func (suite *identityTestSuite) SetupSuite() {
	conf.Path = "../.."
	conf.Port = 8080

	cfg, err := conf.LoadConfig()
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	cfg.Persistence.InMem = true

	users, err := persistence.NewUserRepository(cfg.Persistence)
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	passkeysSvc, err := passkeys.NewService(cfg.Providers.Passkeys)
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	svc := identity.NewService(users, passkeysSvc, cfg.Providers)

	suite.svc = svc
	suite.users = users
}

func (suite *identityTestSuite) TestRegister() {
	u, err := suite.svc.Register("user01", "User01", "user01@example.com")
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	u.Register()

	suite.Equal("user01", u.Username)
	suite.Equal("user01@example.com", u.Email)
	suite.Equal(user.Registered, u.Status)

	suite.Equal(user.UserRegistered.String(), u.Events()[0].EventName())
}

func (suite *identityTestSuite) TestRegisterAndVerify() {
	u, err := suite.svc.Register("user02", "User02", "user02@example.com")
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	u.Register()

	suite.Equal("user02", u.Username)
	suite.Equal("user02@example.com", u.Email)
	suite.Equal(user.Registered, u.Status)
	suite.Equal(user.UserRegistered.String(), u.Events()[0].EventName())

	if err := suite.users.Store(u); err != nil {
		suite.Fail(err.Error())
		return
	}

	u, err = suite.svc.OTPVerify("TODO", u.Username)
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	suite.Equal("user02", u.Username)
	suite.Equal("user02@example.com", u.Email)
	suite.Equal(user.Activated, u.Status)
	suite.Equal(user.UserActivated.String(), u.Events()[0].EventName())
}

func (suite *identityTestSuite) TestSignInWithGoogle() {
	token := suite.cfg.Test.Tokens.Google
	if token == "" {
		suite.T().Skip()
		return
	}

	u, err := suite.svc.SignIn(token, user.GOOGLE)
	if err != nil {
		suite.Error(err)
		suite.T().Skip()
		return
	}

	sid := user.SocialID("100043685676652067799")

	suite.Equal("mirror770109", u.Username)
	suite.Equal(user.Activated, u.Status)
	suite.Equal(sid, u.Accounts[0].SocialID)

	suite.Equal(user.UserRegistered.String(), u.Events()[0].EventName())
	suite.Equal(user.UserSocialAccountAdded.String(), u.Events()[1].EventName())
}

func (suite *identityTestSuite) TestSignInWithPasskeys() {
	token := suite.cfg.Test.Tokens.Passkeys
	if token == "" {
		suite.T().Skip()
		return
	}

	_, err := suite.svc.SignIn(token, user.PASSKEYS)
	if err != nil {
		suite.Fail(err.Error())
		return
	}
}

func (suite *identityTestSuite) TearDownSuite() {
	suite.users.Close()
}

func TestIdentityTestSuite(t *testing.T) {
	suite.Run(t, new(identityTestSuite))
}
