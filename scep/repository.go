package scep

import "time"

// Store persists pending one-time challenges; Consume must be atomic.
type Store interface {
	// Command

	Save(challenge, subject string, ttl time.Duration) error
	Consume(challenge string) (subject string, err error)

	// Close the store
	Close() error
}
