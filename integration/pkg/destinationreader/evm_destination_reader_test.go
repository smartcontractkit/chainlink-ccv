package destinationreader

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
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

type stubOffRampStaticConfigGetter struct {
	cfg offramp.OffRampStaticConfig
	err error
}

func (s stubOffRampStaticConfigGetter) GetStaticConfig(*bind.CallOpts) (offramp.OffRampStaticConfig, error) {
	return s.cfg, s.err
}

// TestDeriveRMNRemoteFromOffRamp covers reading the RMN Remote address from the OffRamp's
// constructor-set static config.
func TestDeriveRMNRemoteFromOffRamp(t *testing.T) {
	rmnRemote := common.HexToAddress("0x0000000000000000000000000000000000005678")

	t.Run("returns the RMN remote from the static config", func(t *testing.T) {
		got, err := deriveRMNRemoteFromOffRamp(context.Background(), stubOffRampStaticConfigGetter{
			cfg: offramp.OffRampStaticConfig{RmnRemote: rmnRemote},
		})
		require.NoError(t, err)
		require.Equal(t, rmnRemote, got)
	})

	t.Run("wraps read errors", func(t *testing.T) {
		wantErr := errors.New("rpc failed")
		_, err := deriveRMNRemoteFromOffRamp(context.Background(), stubOffRampStaticConfigGetter{err: wantErr})
		require.ErrorIs(t, err, wantErr)
		require.ErrorContains(t, err, "failed to read OffRamp static config")
	})

	t.Run("rejects a zero RMN remote", func(t *testing.T) {
		_, err := deriveRMNRemoteFromOffRamp(context.Background(), stubOffRampStaticConfigGetter{})
		require.ErrorContains(t, err, "zero RMN Remote address")
	})
}
