package configdoc

import (
	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	aggsecrets "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/secrets"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// DocKind distinguishes config docs from secrets docs (affects header wording).
type DocKind int

const (
	KindConfig DocKind = iota
	KindSecrets
)

// Target is one documentation target. It is the single place a doc is declared.
type Target struct {
	// Name identifies the target (e.g. "executor").
	Name string
	// Out is the output path relative to the docs root.
	Out string
	// Kind selects config vs secrets header wording.
	Kind DocKind
	// New returns the fully-populated instance to document: defaults applied,
	// illustrative values for required fields. This single instance replaces
	// per-field example tags and a separate defaulting adapter — it is both the
	// documented values and the freshness oracle.
	New func() any
}

// Targets is the registry of documentation targets. Apps are added incrementally
// (see docs/adr/0011).
var Targets = []Target{
	{Name: "executor", Out: "executor/config.documented.toml", Kind: KindConfig, New: executorDocInstance},
	{Name: "aggregator", Out: "aggregator/config.documented.toml", Kind: KindConfig, New: aggregatorConfigInstance},
	{Name: "aggregator", Out: "aggregator/secrets.documented.toml", Kind: KindSecrets, New: aggregatorSecretsInstance},
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
					{APIKeyEnvVar: "AGGREGATOR_CLIENT1_API_KEY", SecretEnvVar: "AGGREGATOR_CLIENT1_SECRET_KEY"},
				},
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
		Storage: aggsecrets.StorageSecrets{URL: "postgres://user:password@localhost:5432/aggregator?sslmode=disable"},
		Redis:   aggsecrets.RedisSecrets{Password: "your-redis-password"},
		Clients: []aggsecrets.ClientSecret{
			{ClientID: "client-1", APIKey: "<api-key>", SecretKey: "<secret-key>"},
		},
	}
}
