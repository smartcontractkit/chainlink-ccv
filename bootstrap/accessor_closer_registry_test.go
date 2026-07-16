package bootstrap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestAccessorCloserRegistry_CloseAll(t *testing.T) {
	t.Parallel()

	errA := errors.New("close failed A")
	errC := errors.New("close failed C")

	tests := []struct {
		name      string
		closeErrs []error
		wantErr   bool
		wantErrIs []error
	}{
		{
			name:      "closes every handed-out accessor",
			closeErrs: []error{nil, nil, nil}, // 3 accessors, all closing ok
		},
		{
			name:      "aggregates errors",
			closeErrs: []error{errA, nil, errC}, // 3 accessors, 1st and 3rd fail to close
			wantErr:   true,
			wantErrIs: []error{errA, errC},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			accs := make([]*mocks.MockAccessor, len(tt.closeErrs))
			inner := mocks.NewMockAccessorFactory(t)
			for i, closeErr := range tt.closeErrs {
				accs[i] = mocks.NewMockAccessor(t)
				accs[i].EXPECT().Close().Return(closeErr).Once()
				inner.EXPECT().GetAccessor(mock.Anything, mock.Anything).Return(accs[i], nil).Once()
			}

			tr := NewAccessorCloserRegistry(logger.Test(t), inner)
			for range tt.closeErrs {
				_, err := tr.GetAccessor(context.Background(), protocol.ChainSelector(1))
				require.NoError(t, err)
			}

			got := tr.CloseAll()
			if tt.wantErr {
				require.Error(t, got)
				for _, want := range tt.wantErrIs {
					require.ErrorIs(t, got, want)
				}
			} else {
				require.NoError(t, got)
				// Second CloseAll with no intervening GetAccessor: no-op.
				require.NoError(t, tr.CloseAll())
			}
		})
	}
}

func TestAccessorCloserRegistry_Concurrent_GetAccessor(t *testing.T) {
	t.Parallel()
	const n = 50
	accs := make([]*mocks.MockAccessor, n)
	for i := range accs {
		accs[i] = mocks.NewMockAccessor(t)
		accs[i].EXPECT().Close().Return(nil).Once()
	}

	var idx atomic.Int32
	inner := mocks.NewMockAccessorFactory(t)
	inner.EXPECT().GetAccessor(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ protocol.ChainSelector) (chainaccess.Accessor, error) {
			i := int(idx.Add(1)) - 1
			return accs[i], nil
		}).Times(n)

	tr := NewAccessorCloserRegistry(logger.Test(t), inner)

	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := tr.GetAccessor(context.Background(), protocol.ChainSelector(1))
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	require.NoError(t, tr.CloseAll())
}
