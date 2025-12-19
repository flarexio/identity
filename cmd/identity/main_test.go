package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/persistence"
	"github.com/flarexio/identity/user"
)

type identityTestSuite struct {
	suite.Suite
	cfg   *conf.Config
	ps    pubsub.PubSub
	svc   identity.Service
	users user.Repository
}

func (suite *identityTestSuite) SetupSuite() {
	conf.Path = "../.."
	conf.Port = 8080

	ps := pubsub.NewSimplePubSub()

	events.ReplaceGlobals(ps)

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

	suite.cfg = cfg
	suite.ps = ps
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

	eventReceived := make(chan *pubsub.Message, 1)
	if err := suite.ps.Subscribe("users.#.activated", func(ctx context.Context, msg *pubsub.Message) error {
		eventReceived <- msg
		return nil
	}); err != nil {
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

	select {
	case msg := <-eventReceived:
		suite.Contains(msg.Topic, "users."+u.ID.String()+".activated")
	case <-time.After(5 * time.Second):
		suite.Fail("expected user.activated event")
	}
}

func (suite *identityTestSuite) TestSignInWithGoogle() {
	token := suite.cfg.Test.Tokens.Google
	if token == "YOUR_GOOGLE_JWT_TOKEN" {
		suite.T().Skip()
		return
	}

	eventReceived := make(chan *pubsub.Message, 1)
	if err := suite.ps.Subscribe("users.#.#", func(ctx context.Context, msg *pubsub.Message) error {
		eventReceived <- msg
		return nil
	}); err != nil {
		suite.Fail(err.Error())
		return
	}

	ctx := context.Background()
	u, err := suite.svc.SignIn(ctx, token, user.GOOGLE)
	if err != nil {
		suite.Error(err)
		suite.T().Skip()
		return
	}

	sid := user.SocialID("100043685676652067799")

	suite.Equal("mirror770109", u.Username)
	suite.Equal(user.Activated, u.Status)
	suite.Equal(sid, u.Accounts[0].SocialID)

	receivedTopics := make([]string, 3)
	timeout := time.After(5 * time.Second)

	for i := 0; i < 3; i++ {
		select {
		case msg := <-eventReceived:
			receivedTopics[i] = msg.Topic
		case <-timeout:
			suite.Fail("expected user events")
			return
		}
	}

	suite.Contains(receivedTopics[0], "users."+u.ID.String()+".registered")
	suite.Contains(receivedTopics[1], "users."+u.ID.String()+".activated")
	suite.Contains(receivedTopics[2], "users."+u.ID.String()+".social_account_added")
}

func (suite *identityTestSuite) TestSignInWithPasskeys() {
	token := suite.cfg.Test.Tokens.Passkeys
	if token == "YOUR_PASSKEYS_JWT_TOKEN" {
		suite.T().Skip()
		return
	}

	ctx := context.Background()
	_, err := suite.svc.SignIn(ctx, token, user.PASSKEYS)
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
