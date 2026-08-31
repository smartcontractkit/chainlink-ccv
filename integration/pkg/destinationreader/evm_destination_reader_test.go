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

// TestNewEvmDestinationReaderValidatesParams covers the construction-time param checks. They
// matter more now that construction reads the OffRamp's static config on-chain: without them a
// bad address reaches the RPC layer and surfaces as an opaque call failure.
func TestNewEvmDestinationReaderValidatesParams(t *testing.T) {
	const validOffRamp = "0x0000000000000000000000000000000000001234"

	tests := []struct {
		name    string
		params  Params
		wantErr string
	}{
		{
			name:    "rejects an unset chain selector",
			params:  Params{OfframpAddress: validOffRamp},
			wantErr: "chainSelector is not set",
		},
		{
			name:    "rejects an empty off-ramp address",
			params:  Params{ChainSelector: 1},
			wantErr: "offrampAddress is not set",
		},
		{
			name:    "rejects a malformed off-ramp address",
			params:  Params{ChainSelector: 1, OfframpAddress: "0xnothex"},
			wantErr: `offrampAddress "0xnothex" is not a valid EVM address`,
		},
		{
			// common.HexToAddress would silently left-pad this to the zero address.
			name:    "rejects a truncated off-ramp address",
			params:  Params{ChainSelector: 1, OfframpAddress: "0x1234"},
			wantErr: "is not a valid EVM address",
		},
		{
			name:    "rejects a zero off-ramp address",
			params:  Params{ChainSelector: 1, OfframpAddress: "0x0000000000000000000000000000000000000000"},
			wantErr: "offrampAddress is the zero address",
		},
		{
			name:    "rejects a nil chain client",
			params:  Params{ChainSelector: 1, OfframpAddress: validOffRamp},
			wantErr: "chainClient is not set",
		},
		{
			name:    "rejects a nil logger",
			params:  Params{ChainSelector: 1, OfframpAddress: validOffRamp},
			wantErr: "logger is not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validation runs before any RPC, so a nil client never gets dialed here.
			_, err := NewEvmDestinationReader(context.Background(), tt.params)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
