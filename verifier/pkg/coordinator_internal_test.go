package verifier

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/services"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fakeSourceReaderService is a minimal services.Service for exercising startSourceReaderServices
// without standing up a real sourcereader.Service and its DB/RPC dependencies.
type fakeSourceReaderService struct {
	onStart  func()
	startErr error
}

func (f *fakeSourceReaderService) Start(context.Context) error {
	if f.onStart != nil {
		f.onStart()
	}
	return f.startErr
}

func (f *fakeSourceReaderService) Close() error                   { return nil }
func (f *fakeSourceReaderService) Ready() error                   { return nil }
func (f *fakeSourceReaderService) HealthReport() map[string]error { return nil }
func (f *fakeSourceReaderService) Name() string                   { return "fakeSourceReaderService" }

var _ services.Service = (*fakeSourceReaderService)(nil)

func TestStartSourceReaderServices(t *testing.T) {
	t.Parallel()

	t.Run("starts every chain concurrently", func(t *testing.T) {
		t.Parallel()
		const n = 8

		// Peak in-flight starts, not wall-clock, keeps this robust on a loaded CI runner. This is
		// exactly the property that was missing before: Coordinator.Start used to call srs.Start
		// for each chain one at a time, so boot time was the sum of every chain's Start call.
		var inFlight, peak atomic.Int32
		svcs := make(map[protocol.ChainSelector]services.Service, n)
		for i := range n {
			svcs[protocol.ChainSelector(1000+i)] = &fakeSourceReaderService{
				onStart: func() {
					cur := inFlight.Add(1)
					for {
						p := peak.Load()
						if cur <= p || peak.CompareAndSwap(p, cur) {
							break
						}
					}
					time.Sleep(20 * time.Millisecond)
					inFlight.Add(-1)
				},
			}
		}

		err := startSourceReaderServices(context.Background(), svcs)

		require.NoError(t, err)
		require.Greater(t, peak.Load(), int32(1), "chains should start concurrently, not sequentially")
	})

	t.Run("a chain that fails to start reports its own error", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("context deadline exceeded")
		svcs := map[protocol.ChainSelector]services.Service{
			protocol.ChainSelector(1): &fakeSourceReaderService{},
			protocol.ChainSelector(2): &fakeSourceReaderService{startErr: wantErr},
		}

		err := startSourceReaderServices(context.Background(), svcs)

		require.Error(t, err)
		require.ErrorIs(t, err, wantErr)
	})

	t.Run("empty map returns no error", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, startSourceReaderServices(context.Background(), nil))
	})
}
