package rmnremotereader

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"
	"github.com/stretchr/testify/require"
)

func TestLazyRMNRemoteCaller(t *testing.T) {
	t.Parallel()

	t.Run("derives once and caches the successful caller", func(t *testing.T) {
		t.Parallel()

		var derives int32
		mk := func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error) {
			atomic.AddInt32(&derives, 1)
			return rmn_remote.RMNRemoteCaller{}, nil
		}
		l := NewLazyRMNRemoteCaller(mk)

		for i := 0; i < 5; i++ {
			_, err := l.Caller(context.Background())
			require.NoError(t, err)
		}
		require.Equal(t, int32(1), atomic.LoadInt32(&derives))
		require.True(t, l.Derived())
	})

	t.Run("does not cache a transient failure and retries", func(t *testing.T) {
		t.Parallel()

		var derives int32
		mk := func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error) {
			n := atomic.AddInt32(&derives, 1)
			if n < 3 {
				return rmn_remote.RMNRemoteCaller{}, errors.New("RPC call failed: rate limited")
			}
			return rmn_remote.RMNRemoteCaller{}, nil
		}
		l := NewLazyRMNRemoteCaller(mk)

		_, err := l.Caller(context.Background())
		require.Error(t, err)
		require.False(t, l.Derived())

		_, err = l.Caller(context.Background())
		require.Error(t, err)
		require.False(t, l.Derived())

		_, err = l.Caller(context.Background())
		require.NoError(t, err)
		require.True(t, l.Derived())

		// Succeeds from cache; no additional derivation.
		_, err = l.Caller(context.Background())
		require.NoError(t, err)
		require.Equal(t, int32(3), atomic.LoadInt32(&derives))
	})

	t.Run("is safe under concurrent calls", func(t *testing.T) {
		t.Parallel()

		var derives int32
		mk := func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error) {
			atomic.AddInt32(&derives, 1)
			return rmn_remote.RMNRemoteCaller{}, nil
		}
		l := NewLazyRMNRemoteCaller(mk)

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := l.Caller(context.Background())
				require.NoError(t, err)
			}()
		}
		wg.Wait()
		require.Equal(t, int32(1), atomic.LoadInt32(&derives))
	})
}
