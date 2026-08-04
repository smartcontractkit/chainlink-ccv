package migration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobspec"
)

const clVerifierSpec = `schemaVersion = 1
type = "ccvcommitteeverifier"
name = "nop-0-default-verifier"
externalJobID = "2e7a0da8-b5f1-53f7-a95c-436230d41d83"
committeeVerifierConfig = '''
verifier_id = "nop-0-default-verifier"
signer_address = "0x5c69bcd99bb6cfc78d2ef4ce918e16120db23f19"

[committee_verifier_addresses]
  16015286601757825753 = "0x8f3ee3c77D2B27c32306a89D367654F959Db223D"
'''
`

const clExecutorSpec = `schemaVersion = 1
type = "ccvexecutor"
name = "nop-0-default-executor"
externalJobID = "8b1e5f2c-4d3a-5e6f-9a0b-1c2d3e4f5a6b"
executorConfig = '''
executor_id = "nop-0"
indexer_address = ["http://indexer-1:8100"]
'''
`

func TestRetargetVerifierJobSpec(t *testing.T) {
	t.Parallel()

	got, err := RetargetVerifierJobSpec(clVerifierSpec)
	require.NoError(t, err)

	assert.Contains(t, got, "appConfig = '''",
		"a standalone bootstrapper only decodes appConfig")
	assert.NotContains(t, got, "committeeVerifierConfig",
		"the CL-mode envelope must not survive the retarget")

	// The externalJobID is what makes JD treat this as a revision of the operator's existing job
	// rather than a second job standing next to it.
	assert.Contains(t, got, `externalJobID = "2e7a0da8-b5f1-53f7-a95c-436230d41d83"`)
	assert.Contains(t, got, `name = "nop-0-default-verifier"`)
	assert.Contains(t, got, `type = "ccvcommitteeverifier"`)

	// The inner config has to survive untouched: it carries the signer address the committee has
	// registered on chain.
	assert.Contains(t, got, `signer_address = "0x5c69bcd99bb6cfc78d2ef4ce918e16120db23f19"`)
	assert.Contains(t, got, `16015286601757825753 = "0x8f3ee3c77D2B27c32306a89D367654F959Db223D"`)
}

func TestRetargetExecutorJobSpec(t *testing.T) {
	t.Parallel()

	got, err := RetargetExecutorJobSpec(clExecutorSpec)
	require.NoError(t, err)

	assert.Contains(t, got, "appConfig = '''")
	assert.NotContains(t, got, "executorConfig")
	assert.Contains(t, got, `externalJobID = "8b1e5f2c-4d3a-5e6f-9a0b-1c2d3e4f5a6b"`)
	assert.Contains(t, got, `executor_id = "nop-0"`)
	assert.Contains(t, got, `indexer_address = ["http://indexer-1:8100"]`)
}

// The inner config is carried across as text, not decoded and re-marshaled. An operator's running
// job may set keys this devenv build does not know about — a newer field, or one this binary is too
// old to have — and a cutover that silently dropped them would change what the job does. Nor may a
// key whose type has since changed abort the migration: the config is running on the node today.
func TestRetargetPreservesUnknownConfigKeys(t *testing.T) {
	t.Parallel()

	const spec = `schemaVersion = 1
type = "ccvexecutor"
name = "nop-0-default-executor"
externalJobID = "8b1e5f2c-4d3a-5e6f-9a0b-1c2d3e4f5a6b"
executorConfig = '''
executor_id = "nop-0"
indexer_address = ["http://indexer-1:8100"]
some_future_setting = "keep me"

[a_future_section]
  nested = 42
'''
`

	got, err := RetargetExecutorJobSpec(spec)
	require.NoError(t, err)

	assert.Contains(t, got, `some_future_setting = "keep me"`)
	assert.Contains(t, got, "[a_future_section]")
	assert.Contains(t, got, "nested = 42")
	// Formatting is preserved too, since nothing re-serializes the config.
	assert.Contains(t, got, "  nested = 42")
}

func TestRetargetIsIdempotent(t *testing.T) {
	t.Parallel()

	// Re-running the cutover, or running it against an operator already partly migrated, must not
	// corrupt a spec that is already in the standalone shape.
	once, err := RetargetVerifierJobSpec(clVerifierSpec)
	require.NoError(t, err)
	twice, err := RetargetVerifierJobSpec(once)
	require.NoError(t, err)
	assert.Equal(t, once, twice)
}

func TestRetargetRoundTripsThroughTheParser(t *testing.T) {
	t.Parallel()

	// The retargeted spec has to parse back through the same helper devenv uses for drift
	// comparison, or the migrated job will look like it has drifted from the deployment on the
	// next reconcile.
	retargeted, err := RetargetVerifierJobSpec(clVerifierSpec)
	require.NoError(t, err)

	parsed, err := jobspec.ParseVerifierBootstrapJobSpec(retargeted)
	require.NoError(t, err)
	assert.Equal(t, "appConfig", parsed.ConfigFieldName)
	assert.Equal(t, "ccvcommitteeverifier", parsed.Type)
	assert.Contains(t, parsed.AppConfig, "signer_address")
}

func TestRetargetRejectsTheWrongJobType(t *testing.T) {
	t.Parallel()

	// An executor spec fed to the verifier retarget carries executorConfig, which the verifier
	// parser does not accept. Failing here beats proposing a spec the target cannot run.
	_, err := RetargetVerifierJobSpec(clExecutorSpec)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "unknown fields") || strings.Contains(err.Error(), "appConfig"),
		"unexpected error: %v", err)
}
