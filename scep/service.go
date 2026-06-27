package scep

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// ErrChallengeInvalid collapses unknown/used/expired into one error.
var ErrChallengeInvalid = errors.New("challenge invalid")

// Service issues and verifies one-time SCEP enrollment challenges.
type Service interface {
	Generate(subject string) (string, error)
	Verify(challenge string) (subject string, err error)
}

const defaultTTL = 5 * time.Minute

func NewService(store Store, ttl time.Duration) Service {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &service{store: store, ttl: ttl}
}

type service struct {
	store Store
	ttl   time.Duration
}

func (svc *service) Generate(subject string) (string, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(buf)

	if err := svc.store.Save(challenge, subject, svc.ttl); err != nil {
		return "", err
	}
	return challenge, nil
}

func (svc *service) Verify(challenge string) (string, error) {
	if challenge == "" {
		return "", ErrChallengeInvalid
	}
	return svc.store.Consume(challenge)
}
