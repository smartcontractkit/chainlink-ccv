package cursechecker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestIsRemoteChainCursed_SynchronousPollBeforeBackgroundPoll tests that IsRemoteChainCursed
// performs a synchronous poll when state is nil (before background polling has completed).
// This addresses the security finding where chains could be temporarily considered uncursed
// during verifier restart.
func TestIsRemoteChainCursed_SynchronousPollBeforeStart(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	t.Run("cursed lane detected by synchronous poll", func(t *testing.T) {
		// Create mock reader that returns a curse
		mockReader := mocks.NewMockRMNCurseReader(t)
		mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).
			Return([]protocol.Bytes16{ChainSelectorToBytes16(chainB)}, nil).
			Once()

		metrics := mocks.NewMockCurseCheckerMetrics(t)
		metrics.EXPECT().
			SetLocalChainGlobalCursed(mock.Anything, chainA, false).Once()
		metrics.EXPECT().
			SetRemoteChainCursed(mock.Anything, chainA, chainB, true).Once()

		rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
			chainA: mockReader,
		}

		// Create service but DON'T start it - this ensures background polling hasn't run
		svc, err := NewCurseDetectorService(rmnReaders, 1*time.Hour, 5*time.Second, lggr, metrics)
		require.NoError(t, err)

		// Call IsRemoteChainCursed before Start() is called
		// This should trigger a synchronous poll
		cursed, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		require.NoError(t, err)
		assert.True(t, cursed, "Chain B should be detected as cursed via synchronous poll")

		// Verify the mock was called (synchronous poll happened)
		mockReader.AssertExpectations(t)
	})

	t.Run("global curse detected by synchronous poll", func(t *testing.T) {
		// Create mock reader that returns a global curse
		mockReader := mocks.NewMockRMNCurseReader(t)
		mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).
			Return([]protocol.Bytes16{GlobalCurseSubject}, nil).
			Once()

		metrics := mocks.NewMockCurseCheckerMetrics(t)
		metrics.EXPECT().
			SetLocalChainGlobalCursed(mock.Anything, chainA, true).Once()
		// When there's a global curse with no specific remote chains cursed,
		// SetRemoteChainCursed is not called because CursedRemoteChains map is empty

		rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
			chainA: mockReader,
		}

		svc, err := NewCurseDetectorService(rmnReaders, 1*time.Hour, 5*time.Second, lggr, metrics)
		require.NoError(t, err)

		// Call IsRemoteChainCursed before Start() is called
		// This should trigger a synchronous poll and detect global curse
		cursed, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		require.NoError(t, err)
		assert.True(t, cursed, "Any chain should be cursed when global curse is present")
	})

	t.Run("RPC error returns error instead of false", func(t *testing.T) {
		// Create mock reader that returns an error
		mockReader := mocks.NewMockRMNCurseReader(t)
		expectedErr := assert.AnError
		mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).
			Return(nil, expectedErr).
			Once()

		metrics := mocks.NewMockCurseCheckerMetrics(t)

		rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
			chainA: mockReader,
		}

		svc, err := NewCurseDetectorService(rmnReaders, 1*time.Hour, 5*time.Second, lggr, metrics)
		require.NoError(t, err)

		// Call IsRemoteChainCursed - should return error, not false
		cursed, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		assert.Error(t, err, "Should return error when RPC fails")
		assert.False(t, cursed, "Cursed should be false when error occurs")
		assert.Contains(t, err.Error(), "failed to get cursed subjects")
	})

	t.Run("missing RMN reader returns error", func(t *testing.T) {
		// Create service with no reader for chainA
		rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
			chainB: mocks.NewMockRMNCurseReader(t),
		}

		metrics := mocks.NewMockCurseCheckerMetrics(t)

		svc, err := NewCurseDetectorService(rmnReaders, 1*time.Hour, 5*time.Second, lggr, metrics)
		require.NoError(t, err)

		// Try to check curse for chainA which has no reader
		cursed, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		assert.Error(t, err, "Should return error when RMN reader not configured")
		assert.False(t, cursed)
		assert.Contains(t, err.Error(), "RMN reader not configured")
	})

	t.Run("subsequent calls use cached state", func(t *testing.T) {
		// Create mock reader
		mockReader := mocks.NewMockRMNCurseReader(t)
		mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).
			Return([]protocol.Bytes16{ChainSelectorToBytes16(chainB)}, nil).
			Once() // Should only be called once

		metrics := mocks.NewMockCurseCheckerMetrics(t)
		metrics.EXPECT().
			SetLocalChainGlobalCursed(mock.Anything, chainA, false).Once()
		metrics.EXPECT().
			SetRemoteChainCursed(mock.Anything, chainA, chainB, true).Once()

		rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
			chainA: mockReader,
		}

		svc, err := NewCurseDetectorService(rmnReaders, 1*time.Hour, 5*time.Second, lggr, metrics)
		require.NoError(t, err)

		// First call - triggers synchronous poll
		cursed1, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		require.NoError(t, err)
		assert.True(t, cursed1)

		// Second call - should use cached state, no RPC call
		cursed2, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		require.NoError(t, err)
		assert.True(t, cursed2)

		// Third call - still cached
		cursed3, err := svc.IsRemoteChainCursed(ctx, chainA, chainB)
		require.NoError(t, err)
		assert.True(t, cursed3)

		// Verify mock was only called once
		mockReader.AssertExpectations(t)
	})
}
