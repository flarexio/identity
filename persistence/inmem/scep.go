package inmem

import (
	"sync"
	"time"

	"github.com/flarexio/identity/scep"
)

func NewChallengeStore() (scep.Store, error) {
	store := &challengeStore{
		challenges: make(map[string]challenge),
		done:       make(chan struct{}),
	}

	go store.janitor(time.Minute)

	return store, nil
}

type challenge struct {
	subject   string
	expiresAt time.Time
}

type challengeStore struct {
	challenges map[string]challenge
	done       chan struct{}
	once       sync.Once
	sync.Mutex
}

func (s *challengeStore) Save(ch, subject string, ttl time.Duration) error {
	s.Lock()
	defer s.Unlock()

	s.challenges[ch] = challenge{
		subject:   subject,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *challengeStore) Consume(ch string) (string, error) {
	s.Lock()
	defer s.Unlock()

	c, ok := s.challenges[ch]
	if !ok {
		return "", scep.ErrChallengeInvalid
	}

	// One-time: delete on first read (lock makes lookup+delete atomic).
	delete(s.challenges, ch)

	if time.Now().After(c.expiresAt) {
		return "", scep.ErrChallengeInvalid
	}

	return c.subject, nil
}

func (s *challengeStore) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *challengeStore) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.purgeExpired()
		}
	}
}

func (s *challengeStore) purgeExpired() {
	now := time.Now()

	s.Lock()
	defer s.Unlock()

	for ch, c := range s.challenges {
		if now.After(c.expiresAt) {
			delete(s.challenges, ch)
		}
	}
}
