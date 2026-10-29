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

// TestLoadPhasedCfgJDOutput verifies the phased [jd] section (a serialized
// JDInfrastructure) is wired back onto cfg.JD.Out and cfg.JDInfra, since the
// lenient Cfg decode drops its jd_output/node_id_map keys.
func TestLoadPhasedCfgJDOutput(t *testing.T) {
	out := map[string]any{
		"version": 1,
		"cldf": map[string]any{
			"addresses": []string{`[{"address":"0x1"}]`},
		},
		"jd": map[string]any{
			"jd_output": map[string]any{
				"use_cache":          true,
				"container_name":     "jd-1",
				"grpc_url":           "127.0.0.1:14231",
				"internal_grpc_url":  "jd-1:14231",
				"wsrpc_url":          "127.0.0.1:8080",
				"internal_wsrpc_url": "jd-1:8080",
			},
			"node_id_map":          map[string]string{"verifier-1": "node_abc"},
			"node_connect_timeout": "7m",
		},
	}
	data, err := toml.Marshal(out)
	require.NoError(t, err)

	cfg, err := loadPhasedCfg(data)
	require.NoError(t, err)

	require.NotNil(t, cfg.JD)
	require.NotNil(t, cfg.JD.Out)
	assert.Equal(t, "jd-1", cfg.JD.Out.ContainerName)
	assert.Equal(t, "127.0.0.1:14231", cfg.JD.Out.ExternalGRPCUrl)
	assert.Equal(t, "7m", cfg.JD.NodeConnectTimeout)
	require.NotNil(t, cfg.JDInfra)
	assert.Equal(t, map[string]string{"verifier-1": "node_abc"}, cfg.JDInfra.NodeIDMap)
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
