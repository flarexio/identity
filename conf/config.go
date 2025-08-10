package conf

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"time"

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

func LoadConfig() (*Config, error) {
	f, err := os.Open(Path + "/config.yaml")
	if err != nil {
		f, err = os.Open(Path + "/config.example.yaml")
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()

	r := NewEnvExpandedReader(f)

	var cfg *Config
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

type Config struct {
	Name        string      `yaml:"name"`
	BaseURL     string      `yaml:"baseUrl"`
	JWT         JWT         `yaml:"jwt"`
	Persistence Persistence `yaml:"persistence"`
	EventBus    EventBus    `yaml:"eventBus"`
	Providers   Providers   `yaml:"providers"`
	Test        Test        `yaml:"test"`
}

type JWT struct {
	Privkey ed25519.PrivateKey
	Timeout time.Duration
	Refresh struct {
		Enabled bool
		Maximum time.Duration
	}
	Audiences []string
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

	cfg.Audiences = raw.Audiences

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
