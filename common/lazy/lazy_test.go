package lazy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLazy(t *testing.T) {
	t.Parallel()

	type value struct{}

	t.Run("derives once and caches the value", func(t *testing.T) {
		t.Parallel()

		var derives atomic.Int32
		l := New(func(ctx context.Context) (value, error) {
			derives.Add(1)
			return value{}, nil
		})

		for range 5 {
			got, err := l.Value(context.Background())
			require.NoError(t, err)
			require.Equal(t, value{}, got)
		}
		require.Equal(t, int32(1), derives.Load())
		require.True(t, l.Derived())
	})

	t.Run("does not cache a transient failure and retries", func(t *testing.T) {
		t.Parallel()

		var derives atomic.Int32
		l := New(func(ctx context.Context) (value, error) {
			n := derives.Add(1)
			if n < 3 {
				return value{}, errors.New("RPC call failed: rate limited")
			}
			return value{}, nil
		})

		_, err := l.Value(context.Background())
		require.Error(t, err)
		require.False(t, l.Derived())

		_, err = l.Value(context.Background())
		require.Error(t, err)
		require.False(t, l.Derived())

		_, err = l.Value(context.Background())
		require.NoError(t, err)
		require.True(t, l.Derived())

		// Succeeds from cache; no additional derivation.
		_, err = l.Value(context.Background())
		require.NoError(t, err)
		require.Equal(t, int32(3), derives.Load())
	})

	t.Run("returns the derivation error to the caller", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("boom")
		l := New(func(context.Context) (value, error) { return value{}, wantErr })

		_, err := l.Value(context.Background())
		require.ErrorIs(t, err, wantErr)
	})

	t.Run("is safe under concurrent calls", func(t *testing.T) {
		t.Parallel()

		var derives atomic.Int32
		l := New(func(ctx context.Context) (value, error) {
			derives.Add(1)
			return value{}, nil
		})

		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				_, err := l.Value(context.Background())
				require.NoError(t, err)
			})
		}
		wg.Wait()
		require.Equal(t, int32(1), derives.Load())
	})
}
