package bootstrap

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// validEd25519PublicKeyHex is 32 bytes (64 hex chars) for use in JD config tests.
const validEd25519PublicKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// infraMeta returns a toml.MetaData indicating all four infra sections (jd, db, keystore, server)
// are present. Under mode-driven validation, md only affects the static-mode "ignored infra"
// warning; the infra bundle is validated based on needsInfra, not on md.
func infraMeta(t *testing.T) toml.MetaData {
	t.Helper()
	var dummy Config
	md, err := toml.Decode(`
[jd]
server_wsrpc_url = ""
server_csa_public_key = ""
[db]
url = ""
[keystore]
password = ""
[server]
listen_port = 0
`, &dummy)
	require.NoError(t, err)
	return md
}

// validBeholderMonitoring returns a fully-populated, enabled beholder monitoring config
// whose Validate() passes, for use in Config validation tests.
func validBeholderMonitoring() *monitoring.Config {
	return &monitoring.Config{
		Enabled: true,
		Type:    "beholder",
		Beholder: monitoring.BeholderConfig{
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
			config:  &Config{JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer},
			wantErr: false,
		},
		{
			name: "invalid JD section",
			config: &Config{
				JD:       JDConfig{ServerWSRPCURL: "", ServerCSAPublicKey: validEd25519PublicKeyHex},
				Keystore: validKeystore,
				DB:       validDB,
				Server:   validServer,
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'jd' section", "ServerWSRPCURL"},
		},
		{
			name: "invalid keystore section",
			config: &Config{
				JD:       validJD,
				Keystore: KeystoreConfig{Password: ""},
				DB:       validDB,
				Server:   validServer,
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'keystore' section", "password"},
		},
		{
			name: "invalid db section",
			config: &Config{
				JD:       validJD,
				Keystore: validKeystore,
				DB:       DBConfig{URL: ""},
				Server:   validServer,
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'db' section", "url"},
		},
		{
			name: "invalid server section",
			config: &Config{
				JD:       validJD,
				Keystore: validKeystore,
				DB:       validDB,
				Server:   ServerConfig{ListenPort: 0},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'server' section", "listen_port"},
		},
		{
			// Monitoring is optional: a nil pointer means the operator did not configure
			// monitoring in the bootstrap config, and validate() must skip it.
			name: "valid with monitoring unset (nil allowed)",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
				Monitoring: nil,
			},
			wantErr: false,
		},
		{
			// Present-but-disabled is honored: monitoring.Config.Validate() is a no-op when
			// Enabled is false, so an explicit "off" passes (and any Beholder values are ignored).
			name: "valid with monitoring present but disabled",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
				Monitoring: &monitoring.Config{Enabled: false},
			},
			wantErr: false,
		},
		{
			name: "valid with monitoring enabled (beholder)",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
				Monitoring: validBeholderMonitoring(),
			},
			wantErr: false,
		},
		{
			name: "invalid monitoring: enabled without type",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
				Monitoring: &monitoring.Config{Enabled: true},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'monitoring' section", "monitoring type is required"},
		},
		{
			name: "invalid monitoring: enabled beholder with non-positive metric interval",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
				Monitoring: &monitoring.Config{
					Enabled: true,
					Type:    "beholder",
					Beholder: monitoring.BeholderConfig{
						MetricReaderInterval: 0,
						TraceSampleRatio:     0.5,
						TraceBatchTimeout:    5,
					},
				},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'monitoring' section", "metric_reader_interval"},
		},
		{
			// validate() uses errors.Join, so a bad section and bad monitoring both surface.
			name: "aggregates errors across db and monitoring sections",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: DBConfig{URL: ""}, Server: validServer,
				Monitoring: &monitoring.Config{Enabled: true},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'db' section", "failed to validate 'monitoring' section"},
		},
	}
	// All table cases above exercise JD mode (needsInfra=true) so the infra bundle is validated.
	infraMD := infraMeta(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate(logger.Test(t), infraMD, true)
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
		cfg := &Config{Monitoring: validBeholderMonitoring()}
		require.NoError(t, cfg.validate(logger.Test(t), toml.MetaData{}, false))
	})

	// Static-TOML mode ignores the infra bundle entirely: an empty/invalid infra config still
	// passes because needsInfra=false, even when md reports infra sections present (they are only
	// warned about, not validated). This is the mode-driven behavior that replaces presence-driven.
	t.Run("static mode ignores present infra (no error)", func(t *testing.T) {
		cfg := &Config{Monitoring: validBeholderMonitoring()}
		require.NoError(t, cfg.validate(logger.Test(t), infraMeta(t), false))
	})

	// Symmetric guard: the same empty infra config in JD mode (needsInfra=true) DOES fail, naming
	// the missing sections — the precise, load-time error that motivated mode-driven validation.
	t.Run("JD mode requires infra (names missing sections)", func(t *testing.T) {
		cfg := &Config{Monitoring: validBeholderMonitoring()}
		err := cfg.validate(logger.Test(t), toml.MetaData{}, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'jd' section")
		require.Contains(t, err.Error(), "failed to validate 'db' section")
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

	infraMD := infraMeta(t)

	t.Run("no chains is valid", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer}
		require.NoError(t, cfg.validate(logger.Test(t), infraMD, true))
	})

	t.Run("valid chains", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
			Chains: []ChainRegistration{{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "137"}},
		}
		require.NoError(t, cfg.validate(logger.Test(t), infraMD, true))
	})

	t.Run("invalid chain entry fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
			Chains: []ChainRegistration{{Type: "NOTACHAIN", ID: "1"}},
		}
		err := cfg.validate(logger.Test(t), infraMD, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
	})
}
