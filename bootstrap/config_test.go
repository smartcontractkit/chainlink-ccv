package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
)

// validEd25519PublicKeyHex is 32 bytes (64 hex chars) for use in JD config tests.
const validEd25519PublicKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
			// Monitoring is validated first and short-circuits, so a bad monitoring section surfaces
			// before any JD-mode section error.
			name: "monitoring validated before JD sections",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: DBConfig{URL: ""}, Server: validServer,
				Monitoring: &monitoring.Config{Enabled: true},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'monitoring' section"},
		},
		{
			// validate() uses errors.Join across JD-mode sections, so multiple bad sections surface.
			name: "aggregates errors across db and server sections",
			config: &Config{
				JD: validJD, Keystore: validKeystore, DB: DBConfig{URL: ""}, Server: ServerConfig{ListenPort: 0},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'db' section", "failed to validate 'server' section"},
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
