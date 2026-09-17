package verifier

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestSourceReadersForChains(t *testing.T) {
	t.Parallel()

	newReaderAccessor := func(t *testing.T) *mocks.MockAccessor {
		acc := mocks.NewMockAccessor(t)
		reader := mocks.NewMockSourceReader(t)
		acc.EXPECT().SourceReader().Return(reader, nil).Once()
		return acc
	}

	t.Run("returns a reader per chain and dials them concurrently", func(t *testing.T) {
		t.Parallel()
		const n = 8
		selectors := make([]protocol.ChainSelector, n)
		accessors := make(map[protocol.ChainSelector]chainaccess.Accessor, n)
		for i := range selectors {
			selectors[i] = protocol.ChainSelector(1000 + i)
			accessors[selectors[i]] = newReaderAccessor(t)
		}

		// The dial must overlap across chains: sequential dialing makes boot time the sum of all
		// dials, which is the failure mode this helper exists to remove. Peak in-flight dials
		// rather than wall-clock keeps the assertion robust on a loaded CI runner.
		var inFlight, peak atomic.Int32
		registry := mocks.NewMockAccessorFactory(t)
		registry.EXPECT().GetAccessor(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, sel protocol.ChainSelector) (chainaccess.Accessor, error) {
				cur := inFlight.Add(1)
				for {
					p := peak.Load()
					if cur <= p || peak.CompareAndSwap(p, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				inFlight.Add(-1)
				return accessors[sel], nil
			}).Times(n)

		got := sourceReadersForChains(context.Background(), logger.Test(t), registry, selectors, nil)

		require.Len(t, got, n)
		require.Greater(t, peak.Load(), int32(1), "chains should be dialed concurrently, not sequentially")
	})

	t.Run("a chain that fails is skipped, the rest still come up", func(t *testing.T) {
		t.Parallel()
		const (
			goodSel       = protocol.ChainSelector(1)
			dialFailSel   = protocol.ChainSelector(2)
			readerFailSel = protocol.ChainSelector(3)
		)

		goodAcc := newReaderAccessor(t)
		readerFailAcc := mocks.NewMockAccessor(t)
		readerFailAcc.EXPECT().SourceReader().Return(nil, errors.New("source reader not available")).Once()

		registry := mocks.NewMockAccessorFactory(t)
		registry.EXPECT().GetAccessor(mock.Anything, goodSel).Return(goodAcc, nil).Once()
		registry.EXPECT().GetAccessor(mock.Anything, dialFailSel).Return(nil, errors.New("dial failed")).Once()
		registry.EXPECT().GetAccessor(mock.Anything, readerFailSel).Return(readerFailAcc, nil).Once()

		got := sourceReadersForChains(context.Background(), logger.Test(t), registry,
			[]protocol.ChainSelector{goodSel, dialFailSel, readerFailSel}, nil)

		require.Len(t, got, 1)
		require.Contains(t, got, goodSel)
	})

	t.Run("empty selector list returns an empty map", func(t *testing.T) {
		t.Parallel()
		registry := mocks.NewMockAccessorFactory(t)
		got := sourceReadersForChains(context.Background(), logger.Test(t), registry, nil, nil)
		require.Empty(t, got)
	})

	t.Run("transform wraps readers and a transform failure skips the chain", func(t *testing.T) {
		t.Parallel()
		const (
			goodSel        = protocol.ChainSelector(1)
			transformFails = protocol.ChainSelector(2)
		)

		registry := mocks.NewMockAccessorFactory(t)
		registry.EXPECT().GetAccessor(mock.Anything, goodSel).Return(newReaderAccessor(t), nil).Once()
		registry.EXPECT().GetAccessor(mock.Anything, transformFails).Return(newReaderAccessor(t), nil).Once()

		wrapped := mocks.NewMockSourceReader(t)
		transform := func(selector protocol.ChainSelector, reader chainaccess.SourceReader) (chainaccess.SourceReader, error) {
			if selector == transformFails {
				return nil, errors.New("instrumentation failed")
			}
			return wrapped, nil
		}

		got := sourceReadersForChains(context.Background(), logger.Test(t), registry,
			[]protocol.ChainSelector{goodSel, transformFails}, transform)

		require.Len(t, got, 1)
		require.Same(t, wrapped, got[goodSel])
	})
}
