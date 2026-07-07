package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
)

// validEd25519PublicKeyHex is 32 bytes (64 hex chars) for use in JD config tests.
const validEd25519PublicKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// validBeholderMonitoring returns a fully-populated, enabled beholder monitoring config
// whose Validate() passes, for use in Config validation tests.
func validBeholderMonitoring() *monitoring.Config {
	return &monitoring.Config{
		Beholder: monitoring.BeholderConfig{
			Enabled:              true,
			MetricReaderInterval: 10,
			TraceSampleRatio:     1.0,
			TraceBatchTimeout:    5,
		},
	}
}

func TestJDConfig_validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *JDConfig
		wantErr     bool
		errContains []string
	}{
		{
			name: "valid",
			config: &JDConfig{
				ServerWSRPCURL:     "ws://localhost:8080/ws",
				ServerCSAPublicKey: validEd25519PublicKeyHex,
			},
			wantErr: false,
		},
		{
			name: "missing ServerWSRPCURL",
			config: &JDConfig{
				ServerWSRPCURL:     "",
				ServerCSAPublicKey: validEd25519PublicKeyHex,
			},
			wantErr:     true,
			errContains: []string{"ServerWSRPCURL is required"},
		},
		{
			name: "missing ServerCSAPublicKey",
			config: &JDConfig{
				ServerWSRPCURL:     "ws://localhost:8080/ws",
				ServerCSAPublicKey: "",
			},
			wantErr:     true,
			errContains: []string{"ServerCSAPublicKey is required"},
		},
		{
			name: "invalid ServerCSAPublicKey not hex",
			config: &JDConfig{
				ServerWSRPCURL:     "ws://localhost:8080/ws",
				ServerCSAPublicKey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			},
			wantErr:     true,
			errContains: []string{"invalid ServerCSAPublicKey", "failed to decode public key"},
		},
		{
			name: "invalid ServerCSAPublicKey wrong length",
			config: &JDConfig{
				ServerWSRPCURL:     "ws://localhost:8080/ws",
				ServerCSAPublicKey: "0123456789abcdef", // 16 hex chars = 8 bytes, need 32
			},
			wantErr:     true,
			errContains: []string{"invalid ServerCSAPublicKey", "not an ed25519 public key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.errContains {
					require.Contains(t, err.Error(), sub)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestKeystoreConfig_validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *KeystoreConfig
		wantErr     bool
		errContains []string
	}{
		{
			name:    "valid",
			config:  &KeystoreConfig{Password: "secret"},
			wantErr: false,
		},
		{
			name:        "missing password",
			config:      &KeystoreConfig{Password: ""},
			wantErr:     true,
			errContains: []string{"field 'password' is required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.errContains {
					require.Contains(t, err.Error(), sub)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDBConfig_validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *DBConfig
		wantErr     bool
		errContains []string
	}{
		{
			name:    "valid",
			config:  &DBConfig{URL: "postgres://localhost:5432/mydb"},
			wantErr: false,
		},
		{
			name:        "missing url",
			config:      &DBConfig{URL: ""},
			wantErr:     true,
			errContains: []string{"field 'url' is required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.errContains {
					require.Contains(t, err.Error(), sub)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServerConfig_validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *ServerConfig
		wantErr     bool
		errContains []string
	}{
		{
			name:    "valid",
			config:  &ServerConfig{ListenPort: 9988},
			wantErr: false,
		},
		{
			name:        "missing listen port",
			config:      &ServerConfig{ListenPort: 0},
			wantErr:     true,
			errContains: []string{"field 'listen_port' is required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.errContains {
					require.Contains(t, err.Error(), sub)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_validate(t *testing.T) {
	validJD := JDConfig{
		ServerWSRPCURL:     "ws://localhost:8080/ws",
		ServerCSAPublicKey: validEd25519PublicKeyHex,
	}
	validKeystore := KeystoreConfig{Password: "secret"}
	validDB := DBConfig{URL: "postgres://localhost:5432/mydb"}
	validServer := ServerConfig{ListenPort: 9988}

	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		errContains []string
	}{
		{
			name:    "valid",
			config:  &Config{NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer}, Secrets: Secrets{Keystore: validKeystore, DB: validDB}},
			wantErr: false,
		},
		{
			name: "invalid JD section",
			config: &Config{
				NonSecretConfig: NonSecretConfig{
					JD:     JDConfig{ServerWSRPCURL: "", ServerCSAPublicKey: validEd25519PublicKeyHex},
					Server: validServer,
				},
				Secrets: Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'jd' section", "ServerWSRPCURL"},
		},
		{
			name: "invalid keystore section",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer},
				Secrets:         Secrets{Keystore: KeystoreConfig{Password: ""}, DB: validDB},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'keystore' section", "password"},
		},
		{
			name: "invalid db section",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer},
				Secrets:         Secrets{Keystore: validKeystore, DB: DBConfig{URL: ""}},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'db' section", "url"},
		},
		{
			name: "invalid server section",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: ServerConfig{ListenPort: 0}},
				Secrets:         Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'server' section", "listen_port"},
		},
		{
			// Monitoring is optional: a nil pointer means the operator did not configure
			// monitoring in the bootstrap config, and validate() must skip it.
			name: "valid with monitoring unset (nil allowed)",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer, Monitoring: nil},
				Secrets:         Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr: false,
		},
		{
			// Present-but-disabled is honored: monitoring.Config.Validate() is a no-op when
			// Enabled is false, so an explicit "off" passes (and any Beholder values are ignored).
			name: "valid with monitoring present but disabled",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer, Monitoring: &monitoring.Config{}},
				Secrets:         Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr: false,
		},
		{
			name: "valid with monitoring enabled (beholder)",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer, Monitoring: validBeholderMonitoring()},
				Secrets:         Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr: false,
		},
		{
			name: "invalid monitoring: enabled beholder with non-positive metric interval",
			config: &Config{
				NonSecretConfig: NonSecretConfig{
					JD:     validJD,
					Server: validServer,
					Monitoring: &monitoring.Config{
						Beholder: monitoring.BeholderConfig{
							Enabled:              true,
							MetricReaderInterval: 0,
							TraceSampleRatio:     0.5,
							TraceBatchTimeout:    5,
						},
					},
				},
				Secrets: Secrets{Keystore: validKeystore, DB: validDB},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'monitoring' section", "metric_reader_interval"},
		},
		{
			// validate() uses errors.Join, so a bad section and bad monitoring both surface.
			name: "aggregates errors across db and monitoring sections",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer, Monitoring: &monitoring.Config{LogLevel: "invalid"}},
				Secrets:         Secrets{Keystore: validKeystore, DB: DBConfig{URL: ""}},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'db' section", "failed to validate 'monitoring' section"},
		},
	}
	// All table cases above exercise JD mode (needsInfra=true) so the infra bundle is validated.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate(true)
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.errContains {
					require.Contains(t, err.Error(), sub)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}

	// A monitoring-only config in static-TOML mode (needsInfra=false) must pass validation.
	t.Run("monitoring-only config (static mode) is valid", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{Monitoring: validBeholderMonitoring()}}
		require.NoError(t, cfg.validate(false))
	})

	// Static-TOML mode ignores the infra bundle entirely: an empty/invalid infra config still
	// passes because needsInfra=false, even when md reports infra sections present (they are only
	// warned about, not validated). This is the mode-driven behavior that replaces presence-driven.
	t.Run("static mode ignores present infra (no error)", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{Monitoring: validBeholderMonitoring()}}
		require.NoError(t, cfg.validate(false))
	})

	// Symmetric guard: the same empty infra config in JD mode (needsInfra=true) DOES fail, naming
	// the missing sections — the precise, load-time error that motivated mode-driven validation.
	t.Run("JD mode requires infra (names missing sections)", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{Monitoring: validBeholderMonitoring()}}
		err := cfg.validate(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'jd' section")
		require.Contains(t, err.Error(), "failed to validate 'db' section")
	})
}

// writeFile writes content to a fresh file under dir and returns its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// TestLoadAndValidateConfig exercises the config/secrets split load path: the legacy
// monolithic layout, the split layout, secrets-file precedence on overlap, and that validation runs
// on the merged struct regardless of which file supplied a section.
func TestLoadAndValidateConfig(t *testing.T) {
	const nonSecretTOML = `
[jd]
server_wsrpc_url = "ws://localhost:8080/ws"
server_csa_public_key = "` + validEd25519PublicKeyHex + `"

[server]
listen_port = 9988

[[chains]]
type = "EVM"
id = "1"
`
	const secretsTOML = `
[keystore]
password = "s3cret"

[db]
url = "postgres://localhost:5432/bootstrapper"
`
	const monolithTOML = nonSecretTOML + secretsTOML

	assertFullyPopulated := func(t *testing.T, cfg *Config) {
		t.Helper()
		require.Equal(t, "ws://localhost:8080/ws", cfg.JD.ServerWSRPCURL)
		require.Equal(t, 9988, cfg.Server.ListenPort)
		require.Len(t, cfg.Chains, 1)
		require.Equal(t, "s3cret", cfg.Keystore.Password)
		require.Equal(t, "postgres://localhost:5432/bootstrapper", cfg.DB.URL)
	}

	t.Run("legacy monolith: single file with all sections is valid", func(t *testing.T) {
		dir := t.TempDir()
		path := writeFile(t, dir, "config.toml", monolithTOML)

		cfg := &Config{}
		require.NoError(t, LoadAndValidateConfig([]string{path}, cfg, true))
		assertFullyPopulated(t, cfg)
	})

	t.Run("split: config file + secrets file merge into one valid config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := writeFile(t, dir, "config.toml", nonSecretTOML)
		secretsPath := writeFile(t, dir, "secrets.toml", secretsTOML)

		cfg := &Config{}
		require.NoError(t, LoadAndValidateConfig([]string{configPath, secretsPath}, cfg, true))
		assertFullyPopulated(t, cfg)
	})

	t.Run("secrets file wins on overlapping section", func(t *testing.T) {
		dir := t.TempDir()
		// config.toml carries a stale [db]; secrets.toml carries the authoritative one.
		staleDB := nonSecretTOML + "\n[db]\nurl = \"postgres://stale/db\"\n"
		configPath := writeFile(t, dir, "config.toml", staleDB)
		secretsPath := writeFile(t, dir, "secrets.toml", secretsTOML)

		cfg := &Config{}
		require.NoError(t, LoadAndValidateConfig([]string{configPath, secretsPath}, cfg, true))
		require.Equal(t, "postgres://localhost:5432/bootstrapper", cfg.DB.URL,
			"the later (secrets) file must overlay and win for a section it defines")
	})

	t.Run("JD mode: missing secret section (no secrets file) fails validation naming it", func(t *testing.T) {
		dir := t.TempDir()
		// Only the non-secret file is provided, simulating a resolved-but-absent secrets file.
		configPath := writeFile(t, dir, "config.toml", nonSecretTOML)

		cfg := &Config{}
		err := LoadAndValidateConfig([]string{configPath}, cfg, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'keystore' section")
		require.Contains(t, err.Error(), "failed to validate 'db' section")
	})

	t.Run("read error names the offending path", func(t *testing.T) {
		cfg := &Config{}
		err := LoadAndValidateConfig([]string{filepath.Join(t.TempDir(), "does-not-exist.toml")}, cfg, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does-not-exist.toml")
	})
}

func TestChainRegistration_validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		chain       ChainRegistration
		wantErr     bool
		errContains string
	}{
		{"valid EVM", ChainRegistration{Type: "EVM", ID: "1"}, false, ""},
		{"valid lowercase evm", ChainRegistration{Type: "evm", ID: "137"}, false, ""},
		{"valid SOLANA", ChainRegistration{Type: "SOLANA", ID: "mainnet"}, false, ""},
		{"missing type", ChainRegistration{Type: "", ID: "1"}, true, "type"},
		{"missing id", ChainRegistration{Type: "EVM", ID: ""}, true, "id"},
		{"unknown type", ChainRegistration{Type: "BITCOIN", ID: "1"}, true, "unknown chain type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.chain.validate()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_validate_Chains(t *testing.T) {
	t.Parallel()

	validJD := JDConfig{ServerWSRPCURL: "ws://localhost:8080/ws", ServerCSAPublicKey: validEd25519PublicKeyHex}
	validKeystore := KeystoreConfig{Password: "password"}
	validDB := DBConfig{URL: "postgres://localhost/test"}
	validServer := ServerConfig{ListenPort: 9988}

	// withChains builds a valid Config carrying the given chains, so each case varies only the chains.
	withChains := func(chains ...ChainRegistration) *Config {
		return &Config{
			NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer, Chains: chains},
			Secrets:         Secrets{Keystore: validKeystore, DB: validDB},
		}
	}

	t.Run("no chains is valid", func(t *testing.T) {
		t.Parallel()
		cfg := withChains()
		require.NoError(t, cfg.validate(true))
	})

	t.Run("valid chains", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "EVM", ID: "137"})
		require.NoError(t, cfg.validate(true))
	})

	t.Run("invalid chain entry fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "NOTACHAIN", ID: "1"})
		err := cfg.validate(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
	})

	t.Run("mixed chain families fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "SOLANA", ID: "mainnet"})
		err := cfg.validate(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), `chain at index 1 has type "SOLANA"`)
		require.Contains(t, err.Error(), `same family (found "EVM" at index 0)`)
	})

	t.Run("mixed chain families is case-insensitive", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "evm", ID: "1"}, ChainRegistration{Type: "EVM", ID: "137"})
		require.NoError(t, cfg.validate(true), "same family in different casing must not be flagged as mixed")
	})

	t.Run("an invalid entry does not mask the family the remaining valid entries share", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "NOTACHAIN", ID: "1"}, ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "SOLANA", ID: "mainnet"})
		err := cfg.validate(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
		require.Contains(t, err.Error(), `chain at index 2 has type "SOLANA"`)
		require.Contains(t, err.Error(), `same family (found "EVM" at index 1)`)
	})
}
