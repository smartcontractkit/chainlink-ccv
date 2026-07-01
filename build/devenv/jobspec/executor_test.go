package jobspec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExecutorBootstrapJobSpec_StandaloneAppConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvexecutor"
name = "job"
externalJobID = "00000000-0000-0000-0000-000000000001"
appConfig = '''
executor_id = "e1"
'''
`
	got, err := ParseExecutorBootstrapJobSpec(spec)
	require.NoError(t, err)
	require.Contains(t, got.AppConfig, `executor_id = "e1"`)
}

func TestParseExecutorBootstrapJobSpec_CLExecutorConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvexecutor"
name = "job"
externalJobID = "00000000-0000-0000-0000-000000000001"
executorConfig = '''
executor_id = "e1"
'''
`
	got, err := ParseExecutorBootstrapJobSpec(spec)
	require.NoError(t, err)
	require.Contains(t, got.AppConfig, `executor_id = "e1"`)
}

func TestParseExecutorBootstrapJobSpec_MissingInnerConfig(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvexecutor"
name = "job"
`
	_, err := ParseExecutorBootstrapJobSpec(spec)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing appConfig and executorConfig")
}

func TestParseExecutorBootstrapJobSpec_RejectsBothEnvelopes(t *testing.T) {
	spec := `schemaVersion = 1
type = "ccvexecutor"
name = "job"
appConfig = '''a'''
executorConfig = '''b'''
`
	_, err := ParseExecutorBootstrapJobSpec(spec)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exactly one of appConfig and executorConfig")
}
