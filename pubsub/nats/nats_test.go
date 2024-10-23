package nats

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/pubsub"
)

type natsTestSuite struct {
	suite.Suite
	cfg    conf.EventBus
	pubSub NATSPubSub
}

func (suite *natsTestSuite) SetupSuite() {
	path, ok := os.LookupEnv("IDENTITY_PATH")
	if !ok {
		path = "../.."
	}

	conf.Path = path
	conf.Port = 8080

	cfg, err := conf.LoadConfig()
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	cfg.EventBus.Users = conf.Users{
		Stream: conf.Stream{
			Name: "TESTS",
			Config: []byte(`{
					"subjects": [
						"tests.>"
					],
					"retention": "interest",
					"storage": "memory"
				}`),
		},
		Consumer: conf.Consumer{
			Name:   "test-1",
			Stream: "TESTS",
			Config: []byte(`{}`),
		},
	}

	pubSub, err := NewNATSPubSub(cfg.Transports.NATS.Internal)
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	stream := cfg.EventBus.Users.Stream
	if err := pubSub.AddStream(stream.Name, stream.Config); err != nil {
		suite.Fail(err.Error())
		return
	}

	suite.cfg = cfg.EventBus
	suite.pubSub = pubSub
}

func (suite *natsTestSuite) TestPublishAndSubscribe() {
	data := make(chan string, 1)

	err := suite.pubSub.Subscribe("tests.#", func(ctx context.Context, msg *pubsub.Message) error {
		data <- string(msg.Data)
		return nil
	})
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	suite.pubSub.Publish("tests.hello", []byte("world"))

	ack := <-data
	suite.Equal("world", ack)
}

func (suite *natsTestSuite) TestPullSubscribe() {
	stream := suite.cfg.Users.Stream
	consumer := suite.cfg.Users.Consumer
	if err := suite.pubSub.AddConsumer(consumer.Name, stream.Name, consumer.Config); err != nil {
		suite.Fail(err.Error())
		return
	}

	data := make(chan string, 1)
	if err := suite.pubSub.PullSubscribe(consumer.Name, stream.Name, func(ctx context.Context, msg *pubsub.Message) error {
		data <- string(msg.Data)
		return nil
	}); err != nil {
		suite.Fail(err.Error())
		return
	}

	suite.pubSub.Publish("tests.hello", []byte("world"))

	ack := <-data
	suite.Equal("world", ack)
}

func (suite *natsTestSuite) TearDownSuite() {
	suite.pubSub.Close()
}

func TestNatsTestSuite(t *testing.T) {
	suite.Run(t, new(natsTestSuite))
}
