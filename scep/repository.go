package scep

import "time"

// Store persists pending one-time challenges. Consume MUST be atomic so a
// challenge can never be redeemed twice.
type Store interface {
	// Command

	Save(challenge, subject string, ttl time.Duration) error
	Consume(challenge string) (subject string, err error)

	// Close the store
	Close() error
}
