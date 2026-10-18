// Package eventsig signs the user events identity publishes, so that its
// projection (and anyone else consuming users.>) applies only events
// identity itself wrote, not whatever else can publish to the subject.
//
// The signature is appended to the event's JSON object as a final "sig"
// field, so consumers that do not verify can keep decoding events as before:
//
//	{...event...,"sig":"<base64url ed25519 signature>"}
//
// It covers the topic as well as the event, so a signed event cannot be
// replayed under another user's subject.
package eventsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/flarexio/core/pubsub"
)

var (
	ErrUnsigned     = errors.New("event is not signed")
	ErrBadSignature = errors.New("event signature does not verify")
	ErrNotObject    = errors.New("event is not a JSON object")
)

const context = "flarexio.identity.event.v1"

var (
	sigField = []byte(`,"sig":"`)
	sigEnd   = []byte(`"}`)
)

func message(topic string, payload []byte) []byte {
	msg := make([]byte, 0, len(context)+len(topic)+len(payload)+2)
	msg = append(msg, context...)
	msg = append(msg, 0)
	msg = append(msg, topic...)
	msg = append(msg, 0)
	return append(msg, payload...)
}

type Signer struct {
	key ed25519.PrivateKey
}

func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key}
}

// Sign returns payload, a JSON object, with its signature appended.
func (s *Signer) Sign(topic string, payload []byte) ([]byte, error) {
	payload = bytes.TrimSpace(payload)
	if len(payload) < 2 || payload[0] != '{' || payload[len(payload)-1] != '}' {
		return nil, ErrNotObject
	}

	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, message(topic, payload)))

	out := make([]byte, 0, len(payload)+len(sigField)+len(sig)+len(sigEnd))
	out = append(out, payload[:len(payload)-1]...)
	out = append(out, sigField...)
	out = append(out, sig...)
	return append(out, sigEnd...), nil
}

type Verifier struct {
	keys []ed25519.PublicKey
}

// NewVerifier accepts events signed by any of keys: the current key plus,
// while rotating, the ones before it.
func NewVerifier(keys ...ed25519.PublicKey) *Verifier {
	return &Verifier{keys}
}

// Verify checks a signed event and returns it as it was before signing.
func (v *Verifier) Verify(topic string, data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if !bytes.HasSuffix(data, sigEnd) {
		return nil, ErrUnsigned
	}

	i := bytes.LastIndex(data, sigField)
	if i < 0 {
		return nil, ErrUnsigned
	}

	encoded := data[i+len(sigField) : len(data)-len(sigEnd)]
	sig, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrUnsigned
	}

	payload := make([]byte, 0, i+1)
	payload = append(payload, data[:i]...)
	payload = append(payload, '}')

	msg := message(topic, payload)
	for _, key := range v.keys {
		if ed25519.Verify(key, msg, sig) {
			return payload, nil
		}
	}

	return nil, ErrBadSignature
}

// Publisher signs everything published through ps.
func Publisher(ps pubsub.PubSub, s *Signer) pubsub.PubSub {
	return &publisher{ps, s}
}

type publisher struct {
	pubsub.PubSub
	signer *Signer
}

func (p *publisher) Publish(topic string, data []byte) error {
	signed, err := p.signer.Sign(topic, data)
	if err != nil {
		return err
	}

	return p.PubSub.Publish(topic, signed)
}
