package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

// JDConfig is the configuration for the Job Distributor.
type JDConfig struct {
	// ServerWSRPCURL is the URL of the Job Distributor server's WebSocket RPC endpoint.
	ServerWSRPCURL string `toml:"server_wsrpc_url"`
	// ServerCSAPublicKey is the public key of the Job Distributor server's CSA key.
	ServerCSAPublicKey string `toml:"server_csa_public_key"`
}

func (c *JDConfig) validate() error {
	if c.ServerWSRPCURL == "" {
		return fmt.Errorf("ServerWSRPCURL is required")
	}
	if c.ServerCSAPublicKey == "" {
		return fmt.Errorf("ServerCSAPublicKey is required")
	}
	if _, err := keys.DecodeEd25519PublicKey(c.ServerCSAPublicKey); err != nil {
		return fmt.Errorf("invalid ServerCSAPublicKey: %w", err)
	}
	return nil
}

// KeystoreConfig is the configuration for the keystore.
type KeystoreConfig struct {
	// Password is the password to the keystore.
	Password string `toml:"password"`

	// keys are the keys the bootstrapper provisions (JD mode only). Resolved from WithKey by
	// ResolveConfig; unexported so it is never read from or written to a TOML file.
	keys []keyToInit
}

func (c *KeystoreConfig) validate() error {
	if c.Password == "" {
		return fmt.Errorf("field 'password' is required")
	}
	return nil
}

// DBConfig is the configuration for the bootstrap database.
type DBConfig struct {
	// URL is the URL to use for saving jobs and the keystore.
	URL string `toml:"url"`
}

func (c *DBConfig) validate() error {
	if c.URL == "" {
		return fmt.Errorf("field 'url' is required")
	}
	return nil
}

// ServerConfig is the configuration for the HTTP info server.
type ServerConfig struct {
	// ListenPort is the port the HTTP server listens on.
	ListenPort int `toml:"listen_port"`
}

func (c *ServerConfig) validate() error {
	if c.ListenPort == 0 {
		return fmt.Errorf("field 'listen_port' is required")
	}
	return nil
}

// Config is the configuration for the bootstrapper.
// Example config:
/*
	[jd]
	server_wsrpc_url = "ws://localhost:8080/ws"
	server_csa_public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	[keystore]
	password = "password"

	[db]
	url = "postgres://localhost:5432/bootstrapper"

	[server]
	listen_port = 9988
*/
type Config struct {
	// AppConfig, when non-nil, is the application config string and switches the bootstrapper to
	// static mode. It can be embedded in the bootstrap config file (app_config) or resolved from a
	// file/inline by ResolveConfig.
	AppConfig *string `toml:"app_config,omitempty"`

	JD       JDConfig       `toml:"jd"`
	Keystore KeystoreConfig `toml:"keystore"`
	DB       DBConfig       `toml:"db"`
	Server   ServerConfig   `toml:"server"`

	// Monitoring is the operator-provided monitoring configuration. It is a pointer to distinguish
	// "operator did not configure monitoring here" (nil) from "explicitly configured, possibly disabled"
	// (non-nil); the commit verifier and executor prefer it and fall back to their app-config Monitoring
	// only when it is nil.
	Monitoring *monitoring.Config `toml:"monitoring,omitempty"`
	// PyroscopeURL is a pyroscope url
	PyroscopeURL string `json:"pyroscope_url" toml:"pyroscope_url"`
	// LogLevel is the service logger level (e.g. "info", "debug"). Empty defaults to "info".
	LogLevel string `toml:"log_level,omitempty"`
}

// zapLevel parses LogLevel, defaulting to info on empty or invalid input.
func (c *Config) zapLevel() zapcore.Level {
	lvl := zapcore.InfoLevel
	if c.LogLevel != "" {
		_ = lvl.UnmarshalText([]byte(c.LogLevel))
	}
	return lvl
}

func (c *Config) validate() error {
	if c.Monitoring == nil {
		return fmt.Errorf("missing 'monitoring' section")
	}
	if err := c.Monitoring.Validate(); err != nil {
		return fmt.Errorf("failed to validate 'monitoring' section: %w", err)
	}
	// Static mode: JD/DB/Keystore/Server are unused.
	if c.AppConfig != nil {
		return nil
	}

	// JD mode: all sections required.
	var errs []error
	if err := c.JD.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'jd' section: %w", err))
	}
	if err := c.Keystore.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'keystore' section: %w", err))
	}
	if err := c.DB.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'db' section: %w", err))
	}
	if err := c.Server.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'server' section: %w", err))
	}
	return errors.Join(errs...)
}

// keyToInit declares a key the bootstrapper must provision, creating it if absent.
type keyToInit struct {
	name    string
	purpose string
	keyType keystore.KeyType
}

// resolver holds the inputs gathered from Options before they are resolved into a final Config.
type resolver struct {
	bootstrapConfig     *Config       // bootstrap config declared via WithBootstrapConfig
	bootstrapConfigPath string        // bootstrap config path declared via WithBootstrapConfigPathEnv
	appConfig           *string       // app config declared via WithAppConfig
	appConfigPath       string        // app config declared via WithAppConfigPathEnv
	keys                []keyToInit   // keys declared via WithKey
	logLevel            zapcore.Level // log level declared via WithLogLevel or WithLogLevelFromEnv
}

type appCommonConfig struct {
	Monitoring *monitoring.Config `toml:"monitoring,omitempty"`
}

// Option configures the bootstrap resolver. See ResolveConfig for how options are turned into a Config.
type Option func(*resolver) error

// WithLogLevel sets the log level for the logger passed to the application.
func WithLogLevel(logLevel zapcore.Level) Option {
	return func(r *resolver) error {
		r.logLevel = logLevel
		return nil
	}
}

// WithLogLevelFromEnv sets the log level from the LOG_LEVEL environment variable,
// falling back to defaultLevel if the variable is unset or invalid.
func WithLogLevelFromEnv(defaultLevel zapcore.Level) Option {
	return func(r *resolver) error {
		r.logLevel = defaultLevel
		if lvlStr := os.Getenv("LOG_LEVEL"); lvlStr != "" {
			var lvl zapcore.Level
			if err := lvl.UnmarshalText([]byte(lvlStr)); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL '%s', defaulting to '%s'\n", lvlStr, defaultLevel)
			} else {
				r.logLevel = lvl
			}
		}
		return nil
	}
}

// WithKey declares a key that the bootstrapper must ensure exists, creating it if absent.
// When no WithKey options are provided, the bootstrapper applies a deprecated default set of
// three keys (CSA, ECDSA signing, EdDSA signing). Passing one or more WithKey options suppresses
// those defaults entirely; the caller is responsible for declaring every key it requires.
func WithKey(name, purpose string, keyType keystore.KeyType) Option {
	return func(r *resolver) error {
		r.keys = append(r.keys, keyToInit{name: name, purpose: purpose, keyType: keyType})
		return nil
	}
}

// WithBootstrapConfig supplies the bootstrap config directly instead of loading it from a file.
func WithBootstrapConfig(cfg Config) Option {
	return func(r *resolver) error {
		r.bootstrapConfig = &cfg
		return nil
	}
}

// WithBootstrapConfigPathEnv todo.
func WithBootstrapConfigPathEnv(env string) Option {
	return func(r *resolver) error {
		path := os.Getenv(env)
		if path == "" {
			return fmt.Errorf("bootstrap config path cannot be empty")
		}
		r.bootstrapConfigPath = path
		return nil
	}
}

// WithAppConfig supplies the application config inline (highest precedence), switching the
// bootstrapper to static mode and bypassing JD.
func WithAppConfig(raw string) Option {
	return func(r *resolver) error {
		r.appConfig = &raw
		return nil
	}
}

// WithAppConfigPathEnv todo.
func WithAppConfigPathEnv(env string) Option {
	return func(r *resolver) error {
		path := os.Getenv(env)
		if path == "" {
			return fmt.Errorf("app config path cannot be empty")
		}
		r.appConfigPath = path
		return nil
	}
}

// ResolveConfig builds the final, fully-resolved Config from options and decides static vs JD mode.
//
// The bootstrap config is required in every mode: the mode is decided from it. Resolution order:
//  1. Bootstrap Config: supplied via WithBootstrapConfig, otherwise loaded from the TOML file at
//     BOOTSTRAPPER_CONFIG_PATH.
//  2. App config (precedence): inline (WithAppConfig) → embedded (Config.AppConfig) → APP_CONFIG_PATH file.
//  3. A resolved app config → static mode. Otherwise → JD mode (uses JD/DB/Keystore/Server + keys).
func ResolveConfig(opts ...Option) (Config, error) {
	var r resolver
	for _, opt := range opts {
		if err := opt(&r); err != nil {
			return Config{}, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	var cfg Config
	switch {
	case r.bootstrapConfig != nil:
		cfg = *r.bootstrapConfig
	case r.bootstrapConfigPath != "":
		if err := loadTOMLConfig(r.bootstrapConfigPath, &cfg); err != nil {
			return Config{}, fmt.Errorf("failed to load bootstrap config: %w", err)
		}
	case r.appConfig != nil:
		cfg = Config{AppConfig: r.appConfig}
	case r.appConfigPath != "":
		raw, err := os.ReadFile(filepath.Clean(r.appConfigPath))
		if err != nil {
			return Config{}, fmt.Errorf("failed to read app config file (%s): %w", r.appConfigPath, err)
		}
		cfg = Config{AppConfig: new(string(raw))}
	default:
		return Config{}, fmt.Errorf("bootstrap config or app config must be specified")
	}

	// In app mode we need to extract monitoring from AppConfig
	if cfg.AppConfig != nil {
		var mon appCommonConfig
		err := parseTOML(*cfg.AppConfig, &mon, false)
		if err != nil {
			return Config{}, fmt.Errorf("failed to parse monitoring from app config: %w", err)
		}
		if mon.Monitoring == nil {
			return Config{}, fmt.Errorf("monitoring should be declared explicitly")
		}
		cfg.Monitoring = mon.Monitoring
	}

	// Keys are provisioned only in JD mode.
	cfg.Keystore.keys = r.keys
	if cfg.AppConfig == nil {
		cfg.Keystore.keys = ensureKeysForJD(r.keys)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("config validation failed: %w", err)
	}
	return cfg, nil
}

// ensureKeysForJD guarantees a CSA key (required for JD authentication) and applies a default key set
// when the caller declared no keys at all.
//
// The default key set is deprecated and should be removed once all apps and integrations declare their
// keys explicitly via WithKey.
func ensureKeysForJD(declared []keyToInit) []keyToInit {
	if len(declared) == 0 {
		return []keyToInit{
			{DefaultCSAKeyName, "csa", keystore.Ed25519},
			{defaultECDSASigningKeyName, "signing", keystore.ECDSA_S256},
			{defaultEdDSASigningKeyName, "signing", keystore.Ed25519},
		}
	}
	for _, k := range declared {
		if k.purpose == "csa" {
			return declared
		}
	}
	return append([]keyToInit{{DefaultCSAKeyName, "csa", keystore.Ed25519}}, declared...)
}

// loadTOMLConfig loads the configuration from a path to a TOML file, in strict mode.
func loadTOMLConfig(path string, cfg *Config) error {
	tomlBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if err := parseTOML(string(tomlBytes), cfg, true); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	return nil
}

func parseTOML[T any](tomlString string, out T, strict bool) error {
	md, err := toml.Decode(tomlString, out)
	if err != nil {
		return fmt.Errorf("failed to decode toml: %w", err)
	}
	if strict && len(md.Undecoded()) > 0 {
		return fmt.Errorf("strict decode failed, found undecoded fields: %+v", md.Undecoded())
	}
	return nil
}
