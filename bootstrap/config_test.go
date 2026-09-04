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
		mode        AppConfigMode
		config      *KeystoreConfig
		wantErr     bool
		errContains []string
	}{
		{
			name:    "valid postgres (default)",
			mode:    AppConfigModeJD,
			config:  &KeystoreConfig{Password: "secret"},
			wantErr: false,
		},
		{
			name:    "valid postgres (explicit)",
			mode:    AppConfigModeJD,
			config:  &KeystoreConfig{Backend: KeystoreBackendPostgres, Password: "secret"},
			wantErr: false,
		},
		{
			name:        "missing password for postgres",
			mode:        AppConfigModeJD,
			config:      &KeystoreConfig{Password: ""},
			wantErr:     true,
			errContains: []string{"field 'password' is required"},
		},
		{
			name:        "local mode: missing password for postgres",
			mode:        AppConfigModeLocal,
			config:      &KeystoreConfig{Password: ""},
			wantErr:     true,
			errContains: []string{"field 'password' is required"},
		},
		{
			// ed25519_key_id is required for KMS in JD mode (the JD CSA key is Ed25519); an
			// ecdsa-only config is rejected at validation instead of failing later during
			// keystore init.
			name: "JD mode: kms with only ecdsa key is invalid",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-key-id"},
			},
			wantErr:     true,
			errContains: []string{"'ed25519_key_id' is required"},
		},
		{
			name: "JD mode: valid kms with ed25519 key",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, Ed25519KeyID: "ed25519-key-id"},
			},
			wantErr: false,
		},
		{
			name: "JD mode: valid kms with both keys",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-key-id", Ed25519KeyID: "ed25519-key-id"},
			},
			wantErr: false,
		},
		{
			name: "JD mode: kms with no key IDs",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS},
			},
			wantErr:     true,
			errContains: []string{"'ed25519_key_id' is required"},
		},
		{
			// Local mode has no JD to authenticate to: the CSA key is optional, so an ecdsa-only
			// KMS config is valid. Per-declared-key enforcement happens in buildKMSNameMap.
			name: "local mode: kms with only ecdsa key is valid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-key-id"},
			},
			wantErr: false,
		},
		{
			name: "local mode: kms with no key IDs is valid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS},
			},
			wantErr: false,
		},
		{
			name: "kms without password is valid",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend:  KeystoreBackendKMS,
				Password: "",
				KMS:      KMSKeystoreConfig{Provider: KMSProviderAWS, Ed25519KeyID: "ed25519-key-id"},
			},
			wantErr: false,
		},
		{
			name: "kms requires an explicit provider",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{EcdsaKeyID: "ecdsa-key-id"},
			},
			wantErr:     true,
			errContains: []string{"'provider' is required"},
		},
		{
			// A provider-specific section under the other provider is a misconfiguration that must
			// be rejected, not silently ignored.
			name: "aws section under gcp provider is invalid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS: KMSKeystoreConfig{
					Provider:     KMSProviderGCP,
					EcdsaKeyID:   "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1",
					AWSKMSConfig: &AWSKMSConfig{Profile: "my-profile", Region: "us-east-1"},
				},
			},
			wantErr:     true,
			errContains: []string{"[keystore.kms.aws] section is only valid when provider is \"aws\""},
		},
		{
			name: "gcp section under aws provider is invalid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS: KMSKeystoreConfig{
					Provider:     KMSProviderAWS,
					EcdsaKeyID:   "ecdsa-key-id",
					GCPKMSConfig: &GCPKMSConfig{CredentialsFile: "/etc/bootstrap/gcp-sa.json"},
				},
			},
			wantErr:     true,
			errContains: []string{"[keystore.kms.gcp] section is only valid when provider is \"gcp\""},
		},
		{
			// Both sections can never be valid: provider selects exactly one, so one of the two
			// section/provider checks necessarily fires.
			name: "both provider sections is invalid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS: KMSKeystoreConfig{
					Provider:     KMSProviderAWS,
					EcdsaKeyID:   "ecdsa-key-id",
					AWSKMSConfig: &AWSKMSConfig{Profile: "my-profile"},
					GCPKMSConfig: &GCPKMSConfig{CredentialsFile: "/etc/bootstrap/gcp-sa.json"},
				},
			},
			wantErr:     true,
			errContains: []string{"[keystore.kms.gcp] section is only valid when provider is \"gcp\""},
		},
		{
			// The matching sub-section is optional even when the provider is set: AWS works with the
			// default credential chain (no profile/region) and GCP with ADC (no credentials_file).
			name: "provider with no sub-section is valid",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderGCP, EcdsaKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1"},
			},
			wantErr: false,
		},
		{
			// The gcp provider reuses the same [keystore.kms] config; ed25519 is required in JD mode.
			name: "JD mode: gcp kms with only ecdsa key is invalid",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS:     KMSKeystoreConfig{Provider: KMSProviderGCP, EcdsaKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1"},
			},
			wantErr:     true,
			errContains: []string{"'ed25519_key_id' is required"},
		},
		{
			name: "JD mode: valid gcp kms with both keys",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS: KMSKeystoreConfig{
					Provider:     KMSProviderGCP,
					EcdsaKeyID:   "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1",
					Ed25519KeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/ed25519/cryptoKeyVersions/1",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid kms provider",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: KeystoreBackendKMS,
				KMS: KMSKeystoreConfig{
					Provider:     "gcpkms",
					Ed25519KeyID: "ed25519-key-id",
				},
			},
			wantErr:     true,
			errContains: []string{"'provider' is required", "gcpkms"},
		},
		{
			name: "invalid backend",
			mode: AppConfigModeJD,
			config: &KeystoreConfig{
				Backend: "garbage",
			},
			wantErr:     true,
			errContains: []string{"invalid keystore backend"},
		},
		{
			name: "local mode: invalid backend",
			mode: AppConfigModeLocal,
			config: &KeystoreConfig{
				Backend: "garbage",
			},
			wantErr:     true,
			errContains: []string{"invalid keystore backend"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate(tt.mode)
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

func TestKeystoreConfig_resolveBackend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      KeystoreBackend
		want    KeystoreBackend
		wantErr bool
	}{
		{in: "", want: KeystoreBackendPostgres},
		{in: KeystoreBackendPostgres, want: KeystoreBackendPostgres},
		{in: KeystoreBackendKMS, want: KeystoreBackendKMS},
		{in: "garbage", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			cfg := &KeystoreConfig{Backend: tt.in}
			got, err := cfg.resolveBackend()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "keystore backend")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
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
		{
			name: "valid with KMS backend (no password required, db still required)",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer},
				Secrets: Secrets{
					Keystore: KeystoreConfig{
						Backend: KeystoreBackendKMS,
						KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-key-id", Ed25519KeyID: "ed25519-key-id"},
					},
					DB: validDB,
				},
			},
			wantErr: false,
		},
		{
			name: "KMS backend without ed25519 key ID fails",
			config: &Config{
				NonSecretConfig: NonSecretConfig{JD: validJD, Server: validServer},
				Secrets: Secrets{
					Keystore: KeystoreConfig{
						Backend: KeystoreBackendKMS,
						KMS:     KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-key-id"},
					},
					DB: validDB,
				},
			},
			wantErr:     true,
			errContains: []string{"failed to validate 'keystore' section", "'ed25519_key_id' is required"},
		},
	}
	// All table cases above exercise JD mode (AppConfigModeJD) so the full infra bundle is validated.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate(AppConfigModeJD)
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

	// In local mode the infra bundle is not required; only local_app_config_path must be set.
	t.Run("monitoring + local_app_config_path (local mode) is valid", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{LocalAppConfigPath: "/etc/app.toml", Monitoring: validBeholderMonitoring()}}
		require.NoError(t, cfg.validate(AppConfigModeLocal))
	})

	// Local mode does not require the infra bundle: a config with only local_app_config_path passes
	// (the keystore is initialized only when [db]+[keystore] are present).
	t.Run("local mode ignores missing infra (no error)", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{LocalAppConfigPath: "/etc/app.toml"}}
		require.NoError(t, cfg.validate(AppConfigModeLocal))
	})

	// Symmetric guard: the same empty infra config in JD mode DOES fail, naming the missing
	// sections — the precise, load-time error that motivated mode-driven validation.
	t.Run("JD mode requires infra (names missing sections)", func(t *testing.T) {
		cfg := &Config{NonSecretConfig: NonSecretConfig{Monitoring: validBeholderMonitoring()}}
		err := cfg.validate(AppConfigModeJD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'jd' section")
		require.Contains(t, err.Error(), "failed to validate 'db' section")
	})
}

// TestConfig_validate_LocalMode covers local-mode validation: local_app_config_path is required, but
// the infra bundle (jd/db/keystore/server/chains) is not — a signing service supplies [db]+[keystore]
// and the keystore is initialized only when both are present, while the token verifier omits them.
func TestConfig_validate_LocalMode(t *testing.T) {
	t.Parallel()

	validKeystore := KeystoreConfig{Password: "secret"}
	validDB := DBConfig{URL: "postgres://localhost:5432/mydb"}
	localPath := NonSecretConfig{LocalAppConfigPath: "/etc/app.toml"}

	t.Run("local_app_config_path + keystore + db is valid (no jd, no server)", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{NonSecretConfig: localPath, Secrets: Secrets{Keystore: validKeystore, DB: validDB}}
		require.NoError(t, cfg.validate(AppConfigModeLocal))
	})

	t.Run("local_app_config_path only is valid (keystore-less service like the token verifier)", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{NonSecretConfig: localPath}
		require.NoError(t, cfg.validate(AppConfigModeLocal), "local mode must not require any infra section")
	})

	t.Run("missing local_app_config_path fails naming it", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{}
		err := cfg.validate(AppConfigModeLocal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "local_app_config_path")
	})

	// An explicitly selected backend is resolved at load time so a typo fails there instead of at
	// startup; an unset backend (keystore-less token verifier, or presence-driven postgres) is skipped.
	t.Run("explicit invalid keystore backend fails at load time", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			NonSecretConfig: localPath,
			Secrets:         Secrets{Keystore: KeystoreConfig{Backend: "garbage"}},
		}
		err := cfg.validate(AppConfigModeLocal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'keystore' section")
		require.Contains(t, err.Error(), "invalid keystore backend")
	})

	// Local mode has no JD to authenticate to, so no KMS key ID is required at this layer —
	// ed25519_key_id is optional and per-declared-key enforcement happens in buildKMSNameMap.
	t.Run("explicit kms backend without key IDs is valid", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			NonSecretConfig: localPath,
			Secrets:         Secrets{Keystore: KeystoreConfig{Backend: KeystoreBackendKMS}},
		}
		require.NoError(t, cfg.validate(AppConfigModeLocal))
	})

	t.Run("invalid monitoring still fails in local mode", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{NonSecretConfig: NonSecretConfig{LocalAppConfigPath: "/etc/app.toml", Monitoring: &monitoring.Config{LogLevel: "invalid"}}}
		err := cfg.validate(AppConfigModeLocal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'monitoring' section")
	})
}

func TestConfig_resolveAppConfigMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      AppConfigMode
		want    AppConfigMode
		wantErr bool
	}{
		{in: "", want: AppConfigModeJD}, // default
		{in: AppConfigModeJD, want: AppConfigModeJD},
		{in: AppConfigModeLocal, want: AppConfigModeLocal},
		{in: "garbage", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			cfg := &Config{NonSecretConfig: NonSecretConfig{AppConfigMode: tt.in}}
			got, err := cfg.resolveAppConfigMode()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "app_config_mode")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
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
		_, err := LoadAndValidateConfig([]string{path}, cfg)
		require.NoError(t, err)
		assertFullyPopulated(t, cfg)
	})

	t.Run("split: config file + secrets file merge into one valid config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := writeFile(t, dir, "config.toml", nonSecretTOML)
		secretsPath := writeFile(t, dir, "secrets.toml", secretsTOML)

		cfg := &Config{}
		_, err := LoadAndValidateConfig([]string{configPath, secretsPath}, cfg)
		require.NoError(t, err)
		assertFullyPopulated(t, cfg)
	})

	t.Run("secrets file wins on overlapping section", func(t *testing.T) {
		dir := t.TempDir()
		// config.toml carries a stale [db]; secrets.toml carries the authoritative one.
		staleDB := nonSecretTOML + "\n[db]\nurl = \"postgres://stale/db\"\n"
		configPath := writeFile(t, dir, "config.toml", staleDB)
		secretsPath := writeFile(t, dir, "secrets.toml", secretsTOML)

		cfg := &Config{}
		_, err := LoadAndValidateConfig([]string{configPath, secretsPath}, cfg)
		require.NoError(t, err)
		require.Equal(t, "postgres://localhost:5432/bootstrapper", cfg.DB.URL,
			"the later (secrets) file must overlay and win for a section it defines")
	})

	t.Run("JD mode: missing secret section (no secrets file) fails validation naming it", func(t *testing.T) {
		dir := t.TempDir()
		// Only the non-secret file is provided, simulating a resolved-but-absent secrets file.
		configPath := writeFile(t, dir, "config.toml", nonSecretTOML)

		cfg := &Config{}
		_, err := LoadAndValidateConfig([]string{configPath}, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'keystore' section")
		require.Contains(t, err.Error(), "failed to validate 'db' section")
	})

	t.Run("read error names the offending path", func(t *testing.T) {
		cfg := &Config{}
		_, err := LoadAndValidateConfig([]string{filepath.Join(t.TempDir(), "does-not-exist.toml")}, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does-not-exist.toml")
	})

	// The KMS provider sections decode into their embedded pointer sub-structs: the section's
	// presence allocates the pointer, its absence leaves it nil, and validation enforces that a
	// section matches [keystore.kms].provider. All cases run in JD mode so the keystore section is
	// validated at load time (local mode defers keystore validation to startup).
	t.Run("kms provider sections decode and validate", func(t *testing.T) {
		load := func(t *testing.T, kmsTOML string) *Config {
			t.Helper()
			path := writeFile(t, t.TempDir(), "secrets.toml", nonSecretTOML+kmsTOML)
			cfg := &Config{}
			_, err := LoadAndValidateConfig([]string{path}, cfg)
			require.NoError(t, err)
			return cfg
		}

		t.Run("gcp section decodes into the GCP sub-struct", func(t *testing.T) {
			cfg := load(t, `
[keystore]
backend = "kms"

[keystore.kms]
provider = "gcp"
ecdsa_key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
ed25519_key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/e/cryptoKeyVersions/1"

[keystore.kms.gcp]
credentials_file = "/etc/bootstrap/gcp-sa.json"

[db]
url = "postgres://localhost:5432/bootstrapper"
`)
			require.NotNil(t, cfg.Keystore.KMS.GCPKMSConfig)
			require.Nil(t, cfg.Keystore.KMS.AWSKMSConfig)
			require.Equal(t, "/etc/bootstrap/gcp-sa.json", cfg.Keystore.KMS.GCP().CredentialsFile)
		})

		t.Run("aws section decodes into the AWS sub-struct", func(t *testing.T) {
			cfg := load(t, `
[keystore]
backend = "kms"

[keystore.kms]
provider = "aws"
ecdsa_key_id = "arn:aws:kms:us-east-1:...:key/abc"
ed25519_key_id = "arn:aws:kms:us-east-1:...:key/def"

[keystore.kms.aws]
profile = "my-profile"
region = "us-east-1"

[db]
url = "postgres://localhost:5432/bootstrapper"
`)
			require.NotNil(t, cfg.Keystore.KMS.AWSKMSConfig)
			require.Nil(t, cfg.Keystore.KMS.GCPKMSConfig)
			require.Equal(t, "my-profile", cfg.Keystore.KMS.AWS().Profile)
			require.Equal(t, "us-east-1", cfg.Keystore.KMS.AWS().Region)
		})

		t.Run("mismatched section fails validation end-to-end", func(t *testing.T) {
			dir := t.TempDir()
			path := writeFile(t, dir, "secrets.toml", nonSecretTOML+`
[keystore]
backend = "kms"

[keystore.kms]
provider = "gcp"
ecdsa_key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
ed25519_key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/e/cryptoKeyVersions/1"

[keystore.kms.aws]
profile = "my-profile"

[db]
url = "postgres://localhost:5432/bootstrapper"
`)
			cfg := &Config{}
			_, err := LoadAndValidateConfig([]string{path}, cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), `[keystore.kms.aws] section is only valid when provider is "aws"`)
		})
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
		require.NoError(t, cfg.validate(AppConfigModeJD))
	})

	t.Run("valid chains", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "EVM", ID: "137"})
		require.NoError(t, cfg.validate(AppConfigModeJD))
	})

	t.Run("invalid chain entry fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "NOTACHAIN", ID: "1"})
		err := cfg.validate(AppConfigModeJD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
	})

	t.Run("mixed chain families fails validation", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "SOLANA", ID: "mainnet"})
		err := cfg.validate(AppConfigModeJD)
		require.Error(t, err)
		require.Contains(t, err.Error(), `chain at index 1 has type "SOLANA"`)
		require.Contains(t, err.Error(), `same family (found "EVM" at index 0)`)
	})

	t.Run("mixed chain families is case-insensitive", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "evm", ID: "1"}, ChainRegistration{Type: "EVM", ID: "137"})
		require.NoError(t, cfg.validate(AppConfigModeJD), "same family in different casing must not be flagged as mixed")
	})

	t.Run("an invalid entry does not mask the family the remaining valid entries share", func(t *testing.T) {
		t.Parallel()
		cfg := withChains(ChainRegistration{Type: "NOTACHAIN", ID: "1"}, ChainRegistration{Type: "EVM", ID: "1"}, ChainRegistration{Type: "SOLANA", ID: "mainnet"})
		err := cfg.validate(AppConfigModeJD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid chain at index 0")
		require.Contains(t, err.Error(), `chain at index 2 has type "SOLANA"`)
		require.Contains(t, err.Error(), `same family (found "EVM" at index 1)`)
	})
}
