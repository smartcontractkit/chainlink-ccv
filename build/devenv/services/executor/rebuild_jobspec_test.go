package executor

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// Rebuild must preserve the envelope field the deployment chose per NOP mode: cl-mode/default specs
// keep executorConfig (read by the CL node's ccvexecutor job) and standalone specs keep appConfig
// (read by the local bootstrapper). A fixed field would break one flow and drift against the
// deployment-generated spec.
func TestRebuildExecutorJobSpecPreservesConfigField(t *testing.T) {
	blockchainInfos := map[string]any{
		"5009297550715157269": map[string]any{"chain_id": "1"},
	}

	cases := []struct {
		name  string
		field string
		want  string
		other string
	}{
		{"cl mode keeps executorConfig", "executorConfig", "executorConfig", "appConfig"},
		{"standalone keeps appConfig", "appConfig", "appConfig", "executorConfig"},
		{"empty defaults to appConfig", "", "appConfig", "executorConfig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := bootstrap.JobSpec{
				Name:            "executor-job",
				SchemaVersion:   1,
				Type:            "ccvexecutor",
				AppConfig:       "",
				ConfigFieldName: tc.field,
			}

			specStr, err := RebuildExecutorJobSpecWithBlockchainInfos(base, blockchainInfos)
			require.NoError(t, err)
			require.Contains(t, specStr, tc.want+" = '''")
			require.NotContains(t, specStr, tc.other+" = '''")
			require.Contains(t, specStr, "blockchain_infos")
		})
	}
}
