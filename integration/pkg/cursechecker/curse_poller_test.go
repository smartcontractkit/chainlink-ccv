package cursechecker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestCurseDetectorService_LaneSpecificCurse(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
		chainC protocol.ChainSelector = 3
	)

	// Chain A's RMN Remote says chain B is cursed
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{ChainSelectorToBytes16(chainB)}, nil).
		Maybe()

	// Chain B's RMN Remote has no curses
	mockReaderB := mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, 0, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A -> Chain B should be cursed
	require.True(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA->chainB should be cursed")

	// Chain A -> Chain C should not be cursed
	require.False(t, svc.IsRemoteChainCursed(ctx, chainA, chainC), "chainA->chainC should not be cursed")

	// Chain B -> Chain A should not be cursed - in most real scenarios we curse on both sides but this tests one-way curse
	require.False(t, svc.IsRemoteChainCursed(ctx, chainB, chainA), "chainB->chainA should not be cursed")

	// Chain B -> Chain C should not be cursed
	require.False(t, svc.IsRemoteChainCursed(ctx, chainB, chainC), "chainB->chainC should not be cursed")
}

func TestCurseDetectorService_GlobalCurse(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
		chainC protocol.ChainSelector = 3
	)

	// Chain A has a global curse
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{GlobalCurseSubject}, nil).
		Maybe()

	// Chain B has no curses
	mockReaderB := mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, 0, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A has global curse, so all remotes are considered cursed
	require.True(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA has global curse, chainA->chainB should be cursed")
	require.True(t, svc.IsRemoteChainCursed(ctx, chainA, chainC), "chainA has global curse, chainA->chainC should be cursed")

	// Chain B has no global curse
	require.False(t, svc.IsRemoteChainCursed(ctx, chainB, chainA), "chainB->chainA should not be cursed")
	require.False(t, svc.IsRemoteChainCursed(ctx, chainB, chainC), "chainB->chainC should not be cursed")
}

func TestCurseDetectorService_CurseLifting(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	// Chain A's RMN Remote initially says chain B is cursed
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	// First call returns curse, subsequent calls return no curse
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{ChainSelectorToBytes16(chainB)}, nil).
		Maybe()
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 20*time.Millisecond, 0, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A -> Chain B should be cursed
	require.True(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA->chainB should be cursed")

	// lift the curse
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).Unset()
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()
	// Wait for next poll to pick up the change (curse lifted)
	time.Sleep(50 * time.Millisecond)

	// Chain A -> Chain B should no longer be cursed
	require.False(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA->chainB should no longer be cursed")
}

func TestNewCurseDetectorService_Validation(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	mockReaderA := mocks.NewMockRMNCurseReader(t)

	t.Run("EmptyReadersMap", func(t *testing.T) {
		_, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{},
			2*time.Second,
			0,
			lggr,
		)
		require.Error(t, err, "should fail with empty readers")
	})

	t.Run("NilLogger", func(t *testing.T) {
		mockReader := mocks.NewMockRMNCurseReader(t)
		_, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{1: mockReader},
			2*time.Second,
			0,
			nil,
		)
		require.Error(t, err, "should fail with nil logger")
	})

	t.Run("DefaultPollInterval", func(t *testing.T) {
		mockReader := mocks.NewMockRMNCurseReader(t)
		svc, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{1: mockReader},
			0,
			0,
			lggr,
		)
		require.NoError(t, err)
		require.Equal(t, 2*time.Second, svc.(*PollerService).pollInterval, "should use default poll interval")
	})

	t.Run("DefaultRPCTimeout", func(t *testing.T) {
		mockReader := mocks.NewMockRMNCurseReader(t)
		svc, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{1: mockReader},
			2*time.Second,
			0,
			lggr,
		)
		require.NoError(t, err)
		require.Equal(t, DEFAULT_RPC_TIMEOUT, svc.(*PollerService).curseRPCTimeout, "should use default RPC timeout")
	})

	_ = mockReaderA // Silence unused variable
}

func TestCurseDetectorService_ReaderErrorHandling(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	// Chain A's reader returns an error
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return(nil, errors.New("RPC error")).
		Maybe()

	// Chain B's reader works fine
	mockReaderB := mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{ChainSelectorToBytes16(chainA)}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 50*time.Millisecond, 0, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A should have no curse state (error during fetch)
	require.False(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA should have no curse state due to error")

	// Chain B should work correctly
	require.True(t, svc.IsRemoteChainCursed(ctx, chainB, chainA), "chainB should report chainA as cursed")
}

func TestCurseDetectorService_NilCursedSubjects(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	// Chain A returns nil cursed subjects (valid state - no curses)
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return(nil, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, 0, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Nil cursed subjects should be treated as no curses
	require.False(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "nil cursed subjects should mean no curses")
}

// TestCurseDetectorService_RPCTimeout tests that hanging RPC calls timeout and don't block other chains.
func TestCurseDetectorService_RPCTimeout(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	// Chain A hangs (takes longer than timeout)
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Run(func(ctx context.Context) {
			// Simulate a hanging RPC call by sleeping longer than the timeout
			time.Sleep(200 * time.Millisecond)
		}).
		Return(nil, context.DeadlineExceeded).
		Maybe()

	// Chain B returns quickly with a curse
	mockReaderB := mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{ChainSelectorToBytes16(chainA)}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	// Use a short RPC timeout to make the test fast
	svc, err := NewCurseDetectorService(rmnReaders, 50*time.Millisecond, 100*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Wait a bit for the first poll to complete
	time.Sleep(150 * time.Millisecond)

	// Chain A should have no curse state (timeout during fetch)
	require.False(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA should have no state due to timeout")

	// Chain B should work correctly despite Chain A timing out
	require.True(t, svc.IsRemoteChainCursed(ctx, chainB, chainA), "chainB should report chainA as cursed")
}

// TestCurseDetectorService_AllChainsTimeout tests that if all chains timeout, the service continues polling.
func TestCurseDetectorService_AllChainsTimeout(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
		chainB protocol.ChainSelector = 2
	)

	callCount := 0
	var mu sync.Mutex

	// Both chains initially timeout
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Run(func(ctx context.Context) {
			mu.Lock()
			callCount++
			mu.Unlock()
			time.Sleep(200 * time.Millisecond)
		}).
		Return(nil, context.DeadlineExceeded).
		Times(2)

	// Then Chain A starts working
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Run(func(ctx context.Context) {
			mu.Lock()
			callCount++
			mu.Unlock()
		}).
		Return([]protocol.Bytes16{ChainSelectorToBytes16(chainB)}, nil).
		Maybe()

	mockReaderB := mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Run(func(ctx context.Context) {
			time.Sleep(200 * time.Millisecond)
		}).
		Return(nil, context.DeadlineExceeded).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	// Use short intervals for fast testing
	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, 100*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Wait for multiple poll cycles
	time.Sleep(400 * time.Millisecond)

	// Verify that polling continued despite timeouts (callCount should be >= 3)
	mu.Lock()
	count := callCount
	mu.Unlock()
	require.GreaterOrEqual(t, count, 3, "polling should continue despite timeouts")

	// Eventually Chain A should report Chain B as cursed
	require.True(t, svc.IsRemoteChainCursed(ctx, chainA, chainB), "chainA should eventually report chainB as cursed")
}

// TestCurseDetectorService_ContextCancellation tests that RPC timeout respects parent context cancellation.
func TestCurseDetectorService_ContextCancellation(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	const (
		chainA protocol.ChainSelector = 1
	)

	// Chain A RPC respects context cancellation
	mockReaderA := mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Run(func(ctx context.Context) {
			// Wait for context cancellation
			<-ctx.Done()
		}).
		Return(nil, context.Canceled).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, 5*time.Second, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)

	// Let one poll cycle start
	time.Sleep(50 * time.Millisecond)

	// Stop the service (which cancels the context)
	err = svc.Close()
	require.NoError(t, err)

	// Service should stop cleanly without hanging
}
