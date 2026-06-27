package scep

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// ErrChallengeInvalid collapses unknown/used/expired into one error so the
// webhook never leaks which case it was.
var ErrChallengeInvalid = errors.New("challenge invalid")

// Service issues and verifies one-time SCEP enrollment challenges. Generate
// mints a challenge bound to a subject (embedded in the .mobileconfig); Verify
// consumes it from StepCA's SCEPCHALLENGE webhook and returns that subject.
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
	// 256 bits of entropy.
	buf := make([]byte, 32)
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
