package cursedetector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"

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
	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{chainSelectorToBytes16(chainB)}, nil).
		Maybe()

	// Chain B's RMN Remote has no curses
	mockReaderB := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A -> Chain B should be cursed
	require.True(t, svc.IsRemoteChainCursed(chainA, chainB), "chainA->chainB should be cursed")

	// Chain A -> Chain C should not be cursed
	require.False(t, svc.IsRemoteChainCursed(chainA, chainC), "chainA->chainC should not be cursed")

	// Chain B -> Chain A should not be cursed - in most real scenarios we curse on both sides but this tests one-way curse
	require.False(t, svc.IsRemoteChainCursed(chainB, chainA), "chainB->chainA should not be cursed")

	// Chain B -> Chain C should not be cursed
	require.False(t, svc.IsRemoteChainCursed(chainB, chainC), "chainB->chainC should not be cursed")
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
	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{GlobalCurseSubject}, nil).
		Maybe()

	// Chain B has no curses
	mockReaderB := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A has global curse, so all remotes are considered cursed
	require.True(t, svc.IsRemoteChainCursed(chainA, chainB), "chainA has global curse, chainA->chainB should be cursed")
	require.True(t, svc.IsRemoteChainCursed(chainA, chainC), "chainA has global curse, chainA->chainC should be cursed")

	// Chain B has no global curse
	require.False(t, svc.IsRemoteChainCursed(chainB, chainA), "chainB->chainA should not be cursed")
	require.False(t, svc.IsRemoteChainCursed(chainB, chainC), "chainB->chainC should not be cursed")
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
	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)
	// First call returns curse, subsequent calls return no curse
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{chainSelectorToBytes16(chainB)}, nil).
		Maybe()
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 20*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A -> Chain B should be cursed
	require.True(t, svc.IsRemoteChainCursed(chainA, chainB), "chainA->chainB should be cursed")

	// lift the curse
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).Unset()
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{}, nil).
		Maybe()
	// Wait for next poll to pick up the change (curse lifted)
	time.Sleep(50 * time.Millisecond)

	// Chain A -> Chain B should no longer be cursed
	require.False(t, svc.IsRemoteChainCursed(chainA, chainB), "chainA->chainB should no longer be cursed")
}

func TestNewCurseDetectorService_Validation(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)

	t.Run("EmptyReadersMap", func(t *testing.T) {
		_, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{},
			2*time.Second,
			lggr,
		)
		require.Error(t, err, "should fail with empty readers")
	})

	t.Run("NilLogger", func(t *testing.T) {
		mockReader := protocol_mocks.NewMockRMNCurseReader(t)
		_, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{1: mockReader},
			2*time.Second,
			nil,
		)
		require.Error(t, err, "should fail with nil logger")
	})

	t.Run("DefaultPollInterval", func(t *testing.T) {
		mockReader := protocol_mocks.NewMockRMNCurseReader(t)
		svc, err := NewCurseDetectorService(
			map[protocol.ChainSelector]chainaccess.RMNCurseReader{1: mockReader},
			0,
			lggr,
		)
		require.NoError(t, err)
		require.Equal(t, 2*time.Second, svc.(*Service).pollInterval, "should use default poll interval")
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
	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return(nil, errors.New("RPC error")).
		Maybe()

	// Chain B's reader works fine
	mockReaderB := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderB.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return([]protocol.Bytes16{chainSelectorToBytes16(chainA)}, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
		chainB: mockReaderB,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 50*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Chain A should have no curse state (error during fetch)
	require.False(t, svc.IsRemoteChainCursed(chainA, chainB), "chainA should have no curse state due to error")

	// Chain B should work correctly
	require.True(t, svc.IsRemoteChainCursed(chainB, chainA), "chainB should report chainA as cursed")
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
	mockReaderA := protocol_mocks.NewMockRMNCurseReader(t)
	mockReaderA.EXPECT().GetRMNCursedSubjects(mock.Anything).
		Return(nil, nil).
		Maybe()

	rmnReaders := map[protocol.ChainSelector]chainaccess.RMNCurseReader{
		chainA: mockReaderA,
	}

	svc, err := NewCurseDetectorService(rmnReaders, 100*time.Millisecond, lggr)
	require.NoError(t, err)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Close()

	// Nil cursed subjects should be treated as no curses
	require.False(t, svc.IsRemoteChainCursed(chainA, chainB), "nil cursed subjects should mean no curses")
}
