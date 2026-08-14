package destinationreader

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
)

// TestSetExecutorMonitoring covers the optional chainaccess.ExecutorMonitoringSetter
// capability: the accessor factory builds the reader with no-op monitoring and the executor
// attaches its process-level monitoring before the coordinator starts.
func TestSetExecutorMonitoring(t *testing.T) {
	initial := monitoring.NewNoopExecutorMonitoring()
	dr := &EvmDestinationReader{monitoring: initial}

	replacement := monitoring.NewNoopExecutorMonitoring()
	dr.SetExecutorMonitoring(replacement)
	require.Same(t, replacement, dr.monitoring)

	dr.SetExecutorMonitoring(nil)
	require.Same(t, replacement, dr.monitoring, "nil must not clobber the attached monitoring")
}
