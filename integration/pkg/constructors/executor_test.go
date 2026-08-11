package constructors

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/executor"
)

func TestNormalizeExecutorConfigAppliesDefaults(t *testing.T) {
	const appConfig = `
executor_id = "executor-1"
indexer_address = ["http://indexer:8100"]

[chain_configuration."1"]
rmn_address = "0x1"
off_ramp_address = "0x2"
executor_pool = ["executor-1"]
default_executor_address = "0x3"
`
	var cfg executor.Configuration
	require.NoError(t, (bootstrap.JobSpec{AppConfig: appConfig}).GetAppConfig(&cfg))

	normalized, err := normalizeExecutorConfig(cfg)
	require.NoError(t, err)
	require.Equal(t, 15*time.Second, normalized.BackoffDuration)
	require.Equal(t, time.Hour, normalized.LookbackWindow)
	require.Equal(t, uint64(100), normalized.IndexerQueryLimit)
	require.Equal(t, 5*time.Minute, normalized.ReaderCacheExpiry)
	require.Equal(t, 8*time.Hour, normalized.MaxRetryDuration)
	require.Equal(t, time.Second, normalized.DataNotReadyRetryInterval)
	require.Equal(t, "time.google.com", normalized.NtpServer)
	require.Equal(t, 100, normalized.WorkerCount)
	require.Equal(t, time.Minute, normalized.ChainConfiguration["1"].ExecutionInterval)
}
