package destinationreader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
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

// TestNewEvmDestinationReader_NoEagerRPCAtConstruction guards the regression where the
// constructor eagerly read the OffRamp static config (a GetStaticConfig RPC) to derive the RMN
// Remote address, so a rate-limited provider aborted construction. The RMN Remote is now derived
// lazily on first GetRMNCursedSubjects.
func TestNewEvmDestinationReader_NoEagerRPCAtConstruction(t *testing.T) {
	// A client whose RPC always fails: any eager read performed during construction would fail it.
	rateLimitErr := errors.New("RPC call failed: rate limited")
	client := clienttest.NewClient(t)
	client.On("CallContract", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, rateLimitErr)

	dr, err := NewEvmDestinationReader(context.Background(), Params{
		Lggr:                      logger.Test(t),
		ChainSelector:             1,
		ChainClient:               client,
		OfframpAddress:            "0x0000000000000000000000000000000000001234",
		RmnRemoteAddress:          "", // deprecated, unset
		ExecutionVisabilityWindow: time.Hour,
		Monitoring:                monitoring.NewNoopExecutorMonitoring(),
	})
	require.NoError(t, err, "construction must not fail even when the RPC is unavailable")
	require.NotNil(t, dr)
	require.False(t, dr.rmnRemoteCaller.Derived(),
		"the RMN Remote caller must not be derived during construction")

	// The authoritative RMN Remote address is read lazily at query time, surfacing a transient
	// RPC error here rather than at construction. The failure is not cached, so a later call
	// re-attempts (self-healing once the provider recovers).
	_, err = dr.GetRMNCursedSubjects(context.Background())
	require.ErrorContains(t, err, "failed to read OffRamp static config")
	require.False(t, dr.rmnRemoteCaller.Derived(), "a failed derivation must not be cached")

	_, err = dr.GetRMNCursedSubjects(context.Background())
	require.ErrorContains(t, err, "failed to read OffRamp static config")

	// Exactly two RPCs, both triggered at query time — zero at construction.
	client.AssertNumberOfCalls(t, "CallContract", 2)
}
