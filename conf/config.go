package conf

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/flarexio/core/pubsub"
)

var (
	Path string
	Port int

	global *Config
)

func G() *Config {
	if global == nil {
		panic("configuration not loaded")
	}

	return global
}

func ReplaceGlobals(cfg *Config) {
	global = cfg
}

func LoadEnv(cli *cli.Context) error {
	path := cli.String("path")
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		path = homeDir + "/.flarex/identity"
	}

	Path = path
	Port = cli.Int("port")
	return nil
}

// LoadConfig reads $IDENTITY_PATH/config.yaml. There is deliberately no
// fallback to config.example.yaml: its keys are public, and a service that
// signs tokens with them would accept forgeries from anyone.
func LoadConfig() (*Config, error) {
	return LoadConfigFile(filepath.Join(Path, "config.yaml"))
}

func LoadConfigFile(name string) (*Config, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open config (copy config.example.yaml and replace its keys): %w", err)
	}
	defer f.Close()

	r := NewEnvExpandedReader(f)

	var cfg *Config
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	return cfg, nil
}

func (cfg *Config) Validate() error {
	if cfg.BaseURL == "" {
		return errors.New("baseUrl is required")
	}

	if len(cfg.JWT.Audiences) == 0 {
		return errors.New("jwt.audiences needs at least one entry")
	}

	return nil
}

type Config struct {
	Name        string      `yaml:"name"`
	BaseURL     string      `yaml:"baseUrl"`
	JWT         JWT         `yaml:"jwt"`
	SCEP        SCEP        `yaml:"scep"`
	Persistence Persistence `yaml:"persistence"`
	EventBus    EventBus    `yaml:"eventBus"`
	Providers   Providers   `yaml:"providers"`
	HTTP        HTTP        `yaml:"http"`
	MTLS        MTLS        `yaml:"mtls"`
	Test        Test        `yaml:"test"`
}

// MTLS controls which internal service certificates may call the mTLS
// transport. A client certificate is accepted only if its Subject's
// OrganizationalUnit intersects AllowedOUs.
type MTLS struct {
	AllowedOUs []string `yaml:"allowedOUs"`
}

// HTTP configures the public listener.
type HTTP struct {
	// Proxies whose X-Forwarded-For is believed when working out the client
	// address (for rate limiting and logs). Empty means trust none.
	TrustedProxies []netip.Prefix `yaml:"trustedProxies"`

	// Directory holding the built frontend; empty means $IDENTITY_PATH/web.
	// The frontend is served only if the directory exists.
	Web string `yaml:"web"`
}

type JWT struct {
	Privkey ed25519.PrivateKey
	Timeout time.Duration
	Refresh struct {
		Enabled bool

		// How long after the user last actually authenticated tokens may
		// still be renewed, whether by refresh or by the browser session.
		Maximum time.Duration
	}
	Audiences []string

	// User IDs (not usernames) granted the "admin" role. Usernames are
	// derived from e-mail addresses and are freed when an account is
	// deleted, so anyone could end up holding one.
	Admins []string
}

func (cfg *JWT) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Privkey string
		Timeout string
		Refresh struct {
			Enabled bool
			Maximum string
		}
		Audiences []string
		Admins    []string
	}

	if err := value.Decode(&raw); err != nil {
		return err
	}

	priv, err := base64.StdEncoding.DecodeString(raw.Privkey)
	if err != nil {
		return err
	}

	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key length")
	}

	seed := priv[:ed25519.SeedSize]
	if isZero(seed) {
		return errors.New("jwt.privkey is the placeholder from config.example.yaml; run `identity genkey`")
	}

	if !bytes.Equal(ed25519.NewKeyFromSeed(seed), priv) {
		return errors.New("jwt.privkey: public half does not match the seed")
	}

	cfg.Privkey = ed25519.PrivateKey(priv)

	if raw.Timeout == "" {
		cfg.Timeout = 1 * time.Hour
	} else {
		timeout, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return err
		}

		cfg.Timeout = timeout
	}

	cfg.Refresh.Enabled = raw.Refresh.Enabled
	if !raw.Refresh.Enabled {
		cfg.Refresh.Maximum = 0
	} else {

		if raw.Refresh.Maximum == "" {
			cfg.Refresh.Maximum = 1 * time.Hour
		} else {
			max, err := time.ParseDuration(raw.Refresh.Maximum)
			if err != nil {
				return err
			}

			cfg.Refresh.Maximum = max
		}
	}

	if cfg.Refresh.Enabled && cfg.Refresh.Maximum < cfg.Timeout {
		return errors.New("jwt.refresh.maximum must not be shorter than jwt.timeout")
	}

	for _, admin := range raw.Admins {
		if _, err := ulid.ParseStrict(admin); err != nil {
			return fmt.Errorf("jwt.admins: %q is not a user ID (admins are listed by ID, not username)", admin)
		}
	}

	cfg.Audiences = raw.Audiences
	cfg.Admins = raw.Admins

	return nil
}

func isZero(b []byte) bool {
	return subtle.ConstantTimeCompare(b, make([]byte, len(b))) == 1
}

// SCEP holds the StepCA SCEPCHALLENGE webhook settings.
type SCEP struct {
	WebhookID       string
	WebhookSecret   []byte
	WebhookClientCN string // expected mTLS client cert Subject CN (empty = no check)
}

func (cfg *SCEP) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		WebhookID       string `yaml:"webhookID"`
		WebhookSecret   string `yaml:"webhookSecret"`
		WebhookClientCN string `yaml:"webhookClientCN"`
	}

	if err := value.Decode(&raw); err != nil {
		return err
	}

	cfg.WebhookID = raw.WebhookID
	cfg.WebhookClientCN = raw.WebhookClientCN

	if raw.WebhookSecret == "" {
		return errors.New("scep: webhookSecret is required")
	}

	secret, err := base64.StdEncoding.DecodeString(raw.WebhookSecret)
	if err != nil {
		return err
	}

	if len(secret) < 32 || isZero(secret) {
		return errors.New("scep: webhookSecret must be at least 32 random bytes")
	}

	cfg.WebhookSecret = secret
	return nil
}

type PersistenceDriver int

const (
	SQLite PersistenceDriver = iota
	BadgerDB
	InMem
)

func ParsePersistenceDriver(driver string) (PersistenceDriver, error) {
	switch driver {
	case "sqlite":
		return SQLite, nil
	case "badger":
		return BadgerDB, nil
	case "inmem":
		return InMem, nil
	default:
		return -1, errors.New("driver not supported")
	}
}

func (driver PersistenceDriver) String() string {
	switch driver {
	case SQLite:
		return "sqlite"
	case BadgerDB:
		return "badger"
	case InMem:
		return "inmem"
	default:
		return "unknwon"
	}
}

type Persistence struct {
	Driver   PersistenceDriver
	Name     string
	Host     string
	Port     int
	Username string
	Password string
	InMem    bool
}

func (p *Persistence) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Driver   string `yaml:"driver"`
		Name     string `yaml:"name"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		InMem    bool   `yaml:"inmem"`
	}

	if err := value.Decode(&raw); err != nil {
		return err
	}

	driver, err := ParsePersistenceDriver(raw.Driver)
	if err != nil {
		return err
	}

	p.Driver = driver
	p.Name = raw.Name

	p.Host = raw.Host
	if raw.Host == "" {
		p.Host = Path
	}

	p.Port = raw.Port
	p.Username = raw.Username
	p.Password = raw.Password
	p.InMem = raw.InMem

	return nil
}

type TransportProvider int

const NATS TransportProvider = iota

func ParseTransportProvider(provider string) (TransportProvider, error) {
	switch provider {
	case "nats":
		return NATS, nil
	default:
		return -1, errors.New("provider not supported")
	}
}

func (p TransportProvider) String() string {
	switch p {
	case NATS:
		return "nats"
	default:
		return ""
	}
}

type EventBus struct {
	Provider TransportProvider
	Users    pubsub.StreamConsumer
}

func (e *EventBus) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Provider string                `yaml:"provider"`
		Users    pubsub.StreamConsumer `yaml:"users"`
	}

	if err := value.Decode(&raw); err != nil {
		return err
	}

	provider, err := ParseTransportProvider(raw.Provider)
	if err != nil {
		return err
	}

	e.Provider = provider
	e.Users = raw.Users

	return nil
}

type Providers struct {
	Google   GoogleProvider   `yaml:"google"`
	LINE     LineProvider     `yaml:"line"`
	Passkeys PasskeysProvider `yaml:"passkeys"`
}

type GoogleProvider struct {
	Client OAuthAPI `yaml:"client"`
}

type LineProvider struct {
	Channel     OAuthAPI `yaml:"channel"`
	RedirectURI string   `yaml:"redirectURI"`
}

type PasskeysProvider struct {
	BaseURL     string   `yaml:"baseURL"`
	TenantID    string   `yaml:"tenantID"`
	PasskeysAPI OAuthAPI `yaml:"api"`
	Origins     []string `yaml:"origins"`
	Audience    string   `yaml:"audience"`
}

type OAuthAPI struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type Test struct {
	Tokens struct {
		Google   string `yaml:"google"`
		Passkeys string `yaml:"passkeys"`
	}
}
