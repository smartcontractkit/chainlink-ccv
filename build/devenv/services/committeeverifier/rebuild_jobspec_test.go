package committeeverifier

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// The rebuilt spec is proposed to CL nodes, whose ccvcommitteeverifier job validation rejects an
// empty committeeVerifierConfig. It must therefore carry the config under committeeVerifierConfig,
// not the generic appConfig.
func TestRebuildVerifierJobSpecEmitsCommitteeVerifierConfig(t *testing.T) {
	base := bootstrap.JobSpec{
		Name:          "verifier-job",
		SchemaVersion: 1,
		Type:          "ccvcommitteeverifier",
		AppConfig:     "verifier_id = \"v1\"\n",
	}
	blockchainInfos := map[string]any{
		"5009297550715157269": map[string]any{"chain_id": "1"},
	}

	specStr, err := RebuildVerifierJobSpecWithBlockchainInfos(base, blockchainInfos)
	require.NoError(t, err)
	require.NotContains(t, specStr, "appConfig")

	var got struct {
		Name                    string `toml:"name"`
		Type                    string `toml:"type"`
		CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
	}
	_, err = toml.Decode(specStr, &got)
	require.NoError(t, err)
	require.Equal(t, base.Name, got.Name)
	require.Equal(t, base.Type, got.Type)
	require.NotEmpty(t, got.CommitteeVerifierConfig)
	require.Contains(t, got.CommitteeVerifierConfig, "verifier_id")
	require.Contains(t, got.CommitteeVerifierConfig, "blockchain_infos")
}
