package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// validEd25519PublicKeyHex is 32 bytes (64 hex chars) for use in JD config tests.
const validEd25519PublicKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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

	t.Run("no chains is valid", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer}
		require.NoError(t, cfg.validate())
	})

	t.Run("valid chains", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
			Chains: []ChainRegistration{{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "137"}},
		}
		require.NoError(t, cfg.validate())
	})

	t.Run("invalid chain entry fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			JD: validJD, Keystore: validKeystore, DB: validDB, Server: validServer,
			Chains: []ChainRegistration{{Type: "NOTACHAIN", ID: "1"}},
		}
		err := cfg.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
	})
}
