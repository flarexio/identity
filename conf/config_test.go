package conf

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The example's keys are public. Starting with them would let anyone forge
// tokens, so they must be refused rather than used.
func TestExampleConfigIsRefused(t *testing.T) {
	_, err := LoadConfigFile("../config.example.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "genkey")
}

func TestLoadConfig(t *testing.T) {
	os.Setenv("INSTANCE_NAME", "identity")

	example, err := os.ReadFile("../config.example.yaml")
	require.NoError(t, err)

	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	cfg := strings.Replace(string(example),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		base64.StdEncoding.EncodeToString(priv), 1)
	cfg = strings.Replace(cfg,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), 1)

	dir := t.TempDir()
	Path = dir
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600))

	c, err := LoadConfig()
	require.NoError(t, err)

	assert.Equal(t, "identity", c.Name)
	assert.Equal(t, "identity.flarex.io", c.BaseURL)
	assert.Equal(t, 1*time.Hour, c.JWT.Timeout)
	assert.True(t, c.JWT.Refresh.Enabled)
	assert.Equal(t, 1*time.Hour+30*time.Minute, c.JWT.Refresh.Maximum)
	assert.Equal(t, BadgerDB, c.Persistence.Driver)
	assert.Equal(t, "users", c.Persistence.Name)
	require.Len(t, c.HTTP.TrustedProxies, 1)
	assert.Equal(t, "10.0.0.0/8", c.HTTP.TrustedProxies[0].String())
}

func TestJWTValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key := base64.StdEncoding.EncodeToString(priv)

	mismatched := append([]byte{}, priv...)
	mismatched[40] ^= 1

	cases := map[string]string{
		"admin by username": "privkey: " + key + "\nadmins: [admin]",
		"key halves differ": "privkey: " + base64.StdEncoding.EncodeToString(mismatched),
		"short key":         "privkey: " + base64.StdEncoding.EncodeToString(priv[:32]),
		"refresh too short": "privkey: " + key + "\ntimeout: 2h\nrefresh: {enabled: true, maximum: 1h}",
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.yaml")
			require.NoError(t, os.WriteFile(path, []byte("baseUrl: x\njwt:\n  "+strings.ReplaceAll(doc, "\n", "\n  ")+"\n  audiences: [x]\n"), 0o600))

			_, err := LoadConfigFile(path)
			assert.Error(t, err)
		})
	}
}
