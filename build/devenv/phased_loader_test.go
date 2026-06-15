package ccv

import (
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// TestLoadPhasedCfg verifies that a phased (raw-map) output decodes into a Cfg,
// picking up the aggregators/verifiers plurals the committeeccv component owns
// and deriving the aggregator/indexer endpoint maps from each service's Out.
func TestLoadPhasedCfg(t *testing.T) {
	out := map[string]any{
		"version":     1,
		"blockchains": []*blockchain.Input{{Type: "anvil"}},
		"cldf": map[string]any{
			"addresses":    []string{`[{"address":"0x1"}]`},
			"env_metadata": "meta",
		},
		"aggregators": []*services.AggregatorInput{
			{
				CommitteeName: "committee-a",
				Out: &services.AggregatorOutput{
					ExternalHTTPSUrl: "https://agg:1",
					TLSCACertFile:    "/ca.pem",
				},
			},
			// No Out: skipped in the endpoint maps.
			{CommitteeName: "committee-b"},
		},
		"indexer": []*services.IndexerInput{
			{Out: &services.IndexerOutput{ExternalHTTPURL: "http://idx:1", InternalHTTPURL: "http://idx-internal:1"}},
			{Out: nil},
		},
	}
	data, err := toml.Marshal(out)
	require.NoError(t, err)

	cfg, err := loadPhasedCfg(data)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Version)
	require.Len(t, cfg.Blockchains, 1)
	assert.Equal(t, "anvil", cfg.Blockchains[0].Type)
	assert.Equal(t, []string{`[{"address":"0x1"}]`}, cfg.CLDF.Addresses)
	assert.Equal(t, "meta", cfg.CLDF.EnvMetadata)

	assert.Equal(t, map[string]string{"committee-a": "https://agg:1"}, cfg.AggregatorEndpoints)
	assert.Equal(t, map[string]string{"committee-a": "/ca.pem"}, cfg.AggregatorCACertFiles)
	assert.Equal(t, []string{"http://idx:1"}, cfg.IndexerEndpoints)
	assert.Equal(t, []string{"http://idx-internal:1"}, cfg.IndexerInternalEndpoints)
}

// TestLoadPhasedCfgIgnoresRuntimeKeys confirms the lenient decode tolerates the
// extra non-Cfg keys a raw phased dump carries (it must not error on them).
func TestLoadPhasedCfgIgnoresRuntimeKeys(t *testing.T) {
	data := []byte(`
version = 1
[cldf]
addresses = ['[{"address":"0x1"}]']

[[blockchains]]
type = 'anvil'

[some_unknown_section]
foo = 'bar'
`)
	cfg, err := loadPhasedCfg(data)
	require.NoError(t, err)
	assert.Equal(t, 1, cfg.Version)
	require.Len(t, cfg.Blockchains, 1)
}

// TestStripPrivateKeys verifies that stripPrivateKeys drops "_"-prefixed keys
// and preserves all others, including the version marker.
func TestStripPrivateKeys(t *testing.T) {
	out := map[string]any{
		"version":              1,
		"blockchains":          []*blockchain.Input{{Type: "anvil"}},
		"_env":                 "runtime-only",
		"_shared_tls_certs":    "runtime-only",
		"environment_topology": map[string]any{"x": 1},
	}

	public := stripPrivateKeys(out)

	_, hasEnv := public["_env"]
	_, hasTLS := public["_shared_tls_certs"]
	assert.False(t, hasEnv, "_env should be stripped")
	assert.False(t, hasTLS, "_shared_tls_certs should be stripped")
	assert.Contains(t, public, "blockchains")
	assert.Contains(t, public, "environment_topology")
	assert.Equal(t, 1, public["version"])
}
