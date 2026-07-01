package jobspec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVerifierBootstrapJobSpec_StandaloneAppConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvcommitteeverifier"
name = "job"
externalJobID = "00000000-0000-0000-0000-000000000001"
appConfig = '''
verifier_id = "v1"
'''
`
	got, err := ParseVerifierBootstrapJobSpec(spec)
	require.NoError(t, err)
	require.Contains(t, got.AppConfig, `verifier_id = "v1"`)
}

func TestParseVerifierBootstrapJobSpec_CLCommitteeVerifierConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvcommitteeverifier"
name = "job"
externalJobID = "00000000-0000-0000-0000-000000000001"
committeeVerifierConfig = '''
verifier_id = "v1"
'''
`
	got, err := ParseVerifierBootstrapJobSpec(spec)
	require.NoError(t, err)
	require.Contains(t, got.AppConfig, `verifier_id = "v1"`)
}

func TestParseVerifierBootstrapJobSpec_MissingInnerConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvcommitteeverifier"
name = "job"
`
	_, err := ParseVerifierBootstrapJobSpec(spec)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing appConfig and committeeVerifierConfig")
}

func TestParseVerifierBootstrapJobSpec_RejectsBothEnvelopes(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvcommitteeverifier"
name = "job"
appConfig = '''a'''
committeeVerifierConfig = '''b'''
`
	_, err := ParseVerifierBootstrapJobSpec(spec)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exactly one of appConfig and committeeVerifierConfig")
}
