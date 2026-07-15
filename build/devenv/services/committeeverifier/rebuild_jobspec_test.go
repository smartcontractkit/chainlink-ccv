package committeeverifier

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// Rebuild must preserve the envelope field the deployment chose per NOP mode: cl-mode/default specs
// keep committeeVerifierConfig (required by the CL node's ccvcommitteeverifier validation) and
// standalone specs keep appConfig (read by the local bootstrapper). A fixed field would break one
// flow and drift against the deployment-generated spec.
func TestRebuildVerifierJobSpecPreservesConfigField(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  string
		other string
	}{
		{"cl mode keeps committeeVerifierConfig", "committeeVerifierConfig", "committeeVerifierConfig", "appConfig"},
		{"standalone keeps appConfig", "appConfig", "appConfig", "committeeVerifierConfig"},
		{"empty defaults to appConfig", "", "appConfig", "committeeVerifierConfig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := bootstrap.JobSpec{
				Name:            "verifier-job",
				SchemaVersion:   1,
				Type:            "ccvcommitteeverifier",
				AppConfig:       `verifier_id = "v1"`,
				ConfigFieldName: tc.field,
			}

			specStr, err := RebuildVerifierJobSpec(base)
			require.NoError(t, err)
			require.Contains(t, specStr, tc.want+" = '''")
			require.NotContains(t, specStr, tc.other+" = '''")
			require.Contains(t, specStr, "verifier_id")
			require.NotContains(t, specStr, "blockchain_infos")
		})
	}
}
