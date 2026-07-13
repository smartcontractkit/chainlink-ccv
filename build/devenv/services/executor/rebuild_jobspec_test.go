package executor

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// The rebuilt spec is proposed to CL nodes, which read the executor config from executorConfig.
// It must carry the config under executorConfig, not the generic appConfig.
func TestRebuildExecutorJobSpecEmitsExecutorConfig(t *testing.T) {
	base := bootstrap.JobSpec{
		Name:          "executor-job",
		SchemaVersion: 1,
		Type:          "ccvexecutor",
		AppConfig:     "",
	}
	blockchainInfos := map[string]any{
		"5009297550715157269": map[string]any{"chain_id": "1"},
	}

	specStr, err := RebuildExecutorJobSpecWithBlockchainInfos(base, blockchainInfos)
	require.NoError(t, err)
	require.NotContains(t, specStr, "appConfig")

	var got struct {
		Name           string `toml:"name"`
		Type           string `toml:"type"`
		ExecutorConfig string `toml:"executorConfig"`
	}
	_, err = toml.Decode(specStr, &got)
	require.NoError(t, err)
	require.Equal(t, base.Name, got.Name)
	require.Equal(t, base.Type, got.Type)
	require.NotEmpty(t, got.ExecutorConfig)
	require.Contains(t, got.ExecutorConfig, "blockchain_infos")
}
