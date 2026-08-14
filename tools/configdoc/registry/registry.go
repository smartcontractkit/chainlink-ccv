// Package registry declares this repo's configdoc documentation targets: the
// config/secrets structures of the CCV apps, plus the New() builders that produce
// a fully-populated, valid instance of each. It is the single repo-specific
// consumer of the generic tools/configdoc engine — another repo (e.g. a
// chain-specific integration) imports the engine and declares its own registry
// like this one.
package registry

import (
	"time"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	aggsecrets "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/secrets"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	indexer "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// Targets is the registry of documentation targets. Apps are added incrementally.
var Targets = []configdoc.Target{
	{Name: "executor", Out: "executor/config.documented.toml", Kind: configdoc.KindConfig, New: executorDocInstance},
	{Name: "aggregator", Out: "aggregator/config.documented.toml", Kind: configdoc.KindConfig, New: aggregatorConfigInstance},
	{Name: "aggregator", Out: "aggregator/secrets.documented.toml", Kind: configdoc.KindSecrets, New: aggregatorSecretsInstance},
	{Name: "committee verifier", Out: "verifier/committee/config.documented.toml", Kind: configdoc.KindConfig, New: committeeVerifierConfigInstance},
	{Name: "token verifier", Out: "verifier/token/config.documented.toml", Kind: configdoc.KindConfig, New: tokenVerifierConfigInstance},
	{Name: "verifier", Out: "verifier/secrets.documented.toml", Kind: configdoc.KindSecrets, New: verifierSecretsInstance},
	{Name: "indexer", Out: "indexer/config.documented.toml", Kind: configdoc.KindConfig, New: indexerConfigInstance},
	{Name: "indexer", Out: "indexer/secrets.documented.toml", Kind: configdoc.KindSecrets, New: indexerSecretsInstance},
	{Name: "bootstrap", Out: "bootstrap/config.documented.toml", Kind: configdoc.KindConfig, New: bootstrapConfigInstance},
	{Name: "bootstrap", Out: "bootstrap/secrets.documented.toml", Kind: configdoc.KindSecrets, New: bootstrapSecretsInstance},
	{Name: "monitoring", Out: "common/monitoring.documented.toml", Kind: configdoc.KindConfig, New: monitoringConfigInstance},
	{Name: "evm", Out: "evm/config.documented.toml", Kind: configdoc.KindConfig, New: evmConfigInstance},
}

// executorDocInstance builds a fully-populated, valid executor Configuration
// (illustrative values for required fields) and runs the executor's real
// defaulting (GetNormalizedConfig) to fill defaulted fields. The Monitoring
// field is left zero: it is a deprecated, bootstrap-sourced concern (documented
// separately), so its inlined section shows only zero-value defaults here.
func executorDocInstance() any {
	c := &executor.Configuration{
		IndexerAddress: []string{"http://indexer-1:8080", "http://indexer-2:8080"},
		ExecutorID:     "executor-1",
		ChainConfiguration: map[string]executor.ChainConfiguration{
			"1": {
				DestinationChainConfig: chainaccess.DestinationChainConfig{
					OffRampAddress: "0x00000000000000000000000000000000000000ff",
					RmnAddress:     "0x00000000000000000000000000000000000000ab",
				},
				DefaultExecutorAddress: "0x00000000000000000000000000000000000000ec",
				ExecutorPool:           []string{"executor-1", "executor-2"},
			},
		},
	}
	normalized, err := c.GetNormalizedConfig()
	if err != nil {
		panic("configdoc: executor documented instance is invalid: " + err.Error())
	}
	return normalized
}

// aggregatorConfigInstance builds a documented aggregator config: AggregatorID is
// pinned (SetDefaults would otherwise fill it from os.Hostname, making the doc
// non-deterministic), Committee and one API client are populated so their shapes
// are documented (SetDefaults leaves them nil, which the encoder would omit), and
// SetDefaults fills the remaining defaults. Secret-bearing fields are toml:"-" and
// are documented in the secrets file instead.
func aggregatorConfigInstance() any {
	var heartbeatRedisConfig aggregator.HeartbeatRedisConfig
	heartbeatRedisConfig.SetDefaults()

	c := &aggregator.AggregatorConfig{
		AggregatorID: "aggregator-1",
		Committee: &aggregator.Committee{
			QuorumConfigs: map[string]*aggregator.QuorumConfig{
				"1": {
					SourceVerifierAddress: "0x00000000000000000000000000000000000000a1",
					Signers:               []aggregator.Signer{{Address: "0x00000000000000000000000000000000000000b1"}},
					Threshold:             1,
				},
			},
			DestinationVerifiers: map[string]string{"2": "0x00000000000000000000000000000000000000c2"},
		},
		APIClients: []*aggregator.ClientConfig{
			{
				ClientID: "client-1",
				Enabled:  true,
				Groups:   []string{"default"},
				APIKeyPairs: []*aggregator.APIKeyPairEnv{
					{APIKeyEnvVar: "AGGREGATOR_CLIENT1_API_KEY", SecretEnvVar: "AGGREGATOR_CLIENT1_SECRET_KEY"}, //nolint:gosec // G101: env var names for illustration, not credentials
				},
			},
		},
		Heartbeat: aggregator.HeartbeatConfig{
			Redis: &heartbeatRedisConfig,
		},
		RateLimiting: aggregator.RateLimitingConfig{
			Storage: aggregator.RateLimiterStoreConfig{
				Redis: &aggregator.RateLimiterRedisConfig{KeyPrefix: aggregator.DefaultRateLimiterRedisKeyPrefix},
			},
		},
	}
	c.SetDefaults()
	return c
}

// aggregatorSecretsInstance builds the documented aggregator secrets file with
// obviously-fake placeholder credentials. No defaulting: every field is an example.
func aggregatorSecretsInstance() any {
	return &aggsecrets.File{
		Storage: aggsecrets.StorageSecrets{URL: "postgres://user:password@localhost:5432/aggregator?sslmode=disable"}, //nolint:gosec // G101: placeholder example value in generated docs, not a real credential
		Redis:   aggsecrets.RedisSecrets{Password: "your-redis-password"},
		Clients: []aggsecrets.ClientSecret{
			{ClientID: "client-1", APIKey: "<api-key>", SecretKey: "<secret-key>"},
		},
	}
}

// committeeVerifierConfigInstance builds a documented committee verifier config.
// The committee verifier has no defaulting routine, so every value is an example;
// Monitoring is left zero (deprecated, bootstrap-sourced). The aggregators list is
// populated to document the [[aggregators]] shape. HTTPListenPort carries the real
// default so the reference shows the port the server actually binds.
func committeeVerifierConfigInstance() any {
	return &commit.Config{
		VerifierID:     "committee-verifier-1",
		HTTPListenPort: 8100,
		Aggregators: []commit.AggregatorConnection{
			{
				Name:                "aggregator-1",
				SecretName:          "aggregator_1",
				Address:             "aggregator-1:50051",
				MaxSendMsgSizeBytes: 4194304,
				MaxRecvMsgSizeBytes: 4194304,
			},
		},
		MessageDisablementRulesPollInterval:  "2s",
		MessageDisablementRulesClientTimeout: "500ms",
		SignerAddress:                        "0x00000000000000000000000000000000000000d1",
		CommitteeVerifierAddresses:           map[string]string{"1": "0x00000000000000000000000000000000000000c1"},
		DefaultExecutorOnRampAddresses:       map[string]string{"1": "0x00000000000000000000000000000000000000e1"},
		DisableFinalityCheckers:              []string{},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{"1": "0x00000000000000000000000000000000000000a1"},
			RMNRemoteAddresses: map[string]string{"1": "0x00000000000000000000000000000000000000b1"},
		},
	}
}

// tokenVerifierConfigInstance builds a documented token verifier config. It
// documents the base token-verifier shape; the type-specific cctp/lombard
// sub-configs are polymorphic (selected by type/version and parsed via a custom
// UnmarshalTOML) and are left unset here.
func tokenVerifierConfigInstance() any {
	return &token.Config{
		TokenVerifiers: []token.VerifierConfig{
			{VerifierID: "token-verifier-1", Type: "cctp", Version: "2.0"},
		},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{"1": "0x00000000000000000000000000000000000000a1"},
			RMNRemoteAddresses: map[string]string{"1": "0x00000000000000000000000000000000000000b1"},
		},
	}
}

// verifierSecretsInstance builds the documented verifier secrets file (shared by
// both verifier binaries) with obviously-fake placeholder credentials.
func verifierSecretsInstance() any {
	return &vsecrets.SecretsFile{
		DB: vsecrets.DBSecrets{URL: "postgres://user:password@localhost:5432/verifier?sslmode=disable"}, //nolint:gosec // G101: placeholder example value in generated docs, not a real credential
		Aggregators: []vsecrets.AggregatorSecret{
			{SecretName: "aggregator_1", APIKey: "<api-key>", SecretKey: "<secret-key>"},
		},
	}
}

// indexerConfigInstance builds a documented indexer config. The indexer has no
// SetDefaults (defaults are applied inline during Validate), so this populates a
// representative instance directly, including the documented postgres duration
// defaults. Credential fields (APIKey/Secret/URI) are left empty; they are
// documented in the secrets file and merged in at load time.
func indexerConfigInstance() any {
	return &indexer.Config{
		LogLevel: "info",
		Discoveries: []indexer.DiscoveryConfig{
			{
				AggregatorReaderConfig: indexer.AggregatorReaderConfig{Address: "aggregator-1:50051"},
				Name:                   "aggregator-1",
				PollInterval:           1000,
				Timeout:                5000,
				NtpServer:              "time.google.com",
			},
		},
		Scheduler: indexer.SchedulerConfig{
			TickerInterval:               100,
			VerificationVisibilityWindow: 3600,
			BaseDelay:                    1000,
			MaxDelay:                     60000,
		},
		Pool: indexer.PoolConfig{
			ConcurrentWorkers:  100,
			WorkerTimeout:      30,
			HydrationBatchSize: 100,
		},
		Verifiers: []indexer.VerifierConfig{
			{
				Type:                   indexer.ReaderTypeAggregator,
				Name:                   "aggregator-1",
				IssuerAddresses:        []string{"0x0000000000000000000000000000000000000001"},
				BatchSize:              100,
				MaxBatchWaitTime:       500,
				AggregatorReaderConfig: indexer.AggregatorReaderConfig{Address: "aggregator-1:50051"},
			},
		},
		Storage: indexer.StorageConfig{
			Strategy: indexer.StorageStrategySingle,
			Single: &indexer.SingleStorageConfig{
				Type: indexer.StorageBackendTypePostgres,
				Postgres: &indexer.PostgresConfig{
					MaxOpenConnections: 25,
					MaxIdleConnections: 5,
					ConnMaxLifetime:    common.Duration(30 * time.Minute),
					ConnMaxIdleTime:    common.Duration(5 * time.Minute),
				},
			},
		},
		API: indexer.APIConfig{
			ListenPort:     8100,
			RateLimit:      indexer.RateLimitConfig{Enabled: false},
			TrustedProxies: []string{},
		},
	}
}

// indexerSecretsInstance builds the documented indexer secrets file. Secrets are
// keyed by the string index of the corresponding config entry (e.g. "0").
func indexerSecretsInstance() any {
	return &indexer.SecretsConfig{
		Discoveries: map[string]indexer.DiscoverySecrets{
			"0": {APIKey: "<api-key>", Secret: "<secret>"},
		},
		Verifier: map[string]indexer.VerifierSecrets{
			"0": {APIKey: "<api-key>", Secret: "<secret>"},
		},
		Storage: indexer.StorageSecrets{
			Single: indexer.SingleStorageSecrets{
				Postgres: indexer.PostgresSecrets{URI: "postgres://user:password@localhost:5432/indexer?sslmode=disable"}, //nolint:gosec // G101: placeholder example value in generated docs, not a real credential
			},
		},
	}
}

// bootstrapConfigInstance builds the documented bootstrap non-secret config
// (bootstrap.NonSecretConfig, the half devenv marshals into config.toml). The
// bootstrap config has no defaulting routine, so every value is illustrative. The
// Monitoring section is populated (unlike the executor/committee verifier docs,
// which leave it zero) because this is the operator-provided source of truth for
// monitoring; it reuses monitoringConfigInstance so the two docs stay in lockstep.
//
// KeyImport is populated even though a bootstrapper that is not migrating leaves it out entirely.
// It is a pointer, so leaving it nil documents the section as absent rather than as optional, and
// the operators who need it are the ones who have never run the process before.
func bootstrapConfigInstance() any {
	return &bootstrap.NonSecretConfig{
		AppConfigMode:      bootstrap.AppConfigModeJD,
		LocalAppConfigPath: "/etc/committee-verifier/app.toml",
		JD: bootstrap.JDConfig{
			ServerWSRPCURL:     "ws://job-distributor:8080/ws",
			ServerCSAPublicKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Server: bootstrap.ServerConfig{ListenPort: 9988},
		Chains: []bootstrap.ChainRegistration{
			{Type: "EVM", ID: "1"},
		},
		Monitoring: monitoringConfig(),
		KeyImport: &bootstrap.KeyImport{ //nolint:gosec // G101: password_path is where a password file is mounted, not a password
			Path:         "/etc/ccv/migration/key.json",
			PasswordPath: "/etc/ccv/migration/export-password.txt",
			ExpectedID:   "0x0123456789abcdef0123456789abcdef01234567",
		},
	}
}

// bootstrapSecretsInstance builds the documented bootstrap secrets file
// (bootstrap.Secrets, the half devenv marshals into secrets.toml, loaded via
// BOOTSTRAPPER_SECRETS_PATH) with obviously-fake placeholder credentials.
// The keystore section populates both the postgres password and the KMS fields so the reference
// documents both backends; backend itself defaults to postgres. Struct comments on KeystoreConfig
// and KMSKeystoreConfig describe each field.
func bootstrapSecretsInstance() any {
	return &bootstrap.Secrets{
		Keystore: bootstrap.KeystoreConfig{
			Backend:  bootstrap.KeystoreBackendPostgres,
			Password: "your-keystore-password",
			KMS: bootstrap.KMSKeystoreConfig{
				Profile:      "my-aws-profile",
				Region:       "us-east-1",
				EcdsaKeyID:   "arn:aws:kms:us-east-1:...:key/abc123-...",
				Ed25519KeyID: "arn:aws:kms:us-east-1:...:key/def456-...",
			},
		},
		DB: bootstrap.DBConfig{URL: "postgres://user:password@localhost:5432/bootstrapper?sslmode=disable"}, //nolint:gosec // G101: placeholder example value in generated docs, not a real credential
	}
}

// monitoringConfigInstance is the Target adapter for monitoringConfig.
func monitoringConfigInstance() any { return monitoringConfig() }

// monitoringConfig builds the documented shared monitoring config
// (common/monitoring.Config), the schema of the [Monitoring] section carried by
// the bootstrap config and the deprecated inlined app-config sections. It has no
// defaulting routine, so every value is illustrative. TelemetryAttributes carries
// one entry so its map shape is documented (an empty map is omitted by the encoder).
// It returns the concrete type so the bootstrap config builder can embed it directly.
func monitoringConfig() *monitoring.Config {
	return &monitoring.Config{
		LogLevel: "info",
		Pyroscope: monitoring.PyroscopeConfig{
			Enabled: false,
			URL:     "http://pyroscope:4040",
		},
		Beholder: monitoring.BeholderConfig{
			Enabled:                  false,
			InsecureConnection:       true,
			CACertFile:               "/etc/ssl/certs/otel-collector.pem",
			OtelExporterGRPCEndpoint: "otel-collector:4317",
			OtelExporterHTTPEndpoint: "otel-collector:4318",
			LogStreamingEnabled:      false,
			LogStreamingLevel:        "info",
			MetricReaderInterval:     60,
			TraceSampleRatio:         0.1,
			TraceBatchTimeout:        5,
			TelemetryAttributes:      map[string]string{"env": "production"},
		},
	}
}

func evmConfigInstance() any { return evmConfig() }

func evmConfig() evm.Config {
	return evm.Config{
		Chains: map[string]evm.ChainConfig{
			"1": {
				Nodes: []evm.Node{
					{
						Name:    "node-1",
						HTTPUrl: "http://rpc-url.com",
						WSUrl:   "ws://rpc-url.com",
						Order:   1,
					},
				},
				FinalityDepth: 0,
				TXMBlockTime:  2 * time.Second,
			},
		},
	}
}
