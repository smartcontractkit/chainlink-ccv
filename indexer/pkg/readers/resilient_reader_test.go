package readers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/ratelimiter"
	"github.com/failsafe-go/failsafe-go/timeout"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewResilienceConfig(t *testing.T) {
	def := DefaultResilienceConfig()

	t.Run("validated zero config returns all defaults", func(t *testing.T) {
		in := config.ResilienceConfig{}
		require.NoError(t, in.Validate())
		rc := NewResilienceConfig(in)
		assert.Equal(t, def, rc)
	})

	t.Run("partial overrides keep defaults for unset fields", func(t *testing.T) {
		in := config.ResilienceConfig{
			MaxRequestsPerSecond: 100,
			RequestTimeout:       common.Duration(30 * time.Second),
		}
		require.NoError(t, in.Validate())
		rc := NewResilienceConfig(in)
		assert.Equal(t, uint(100), rc.MaxRequestsPerSecond)
		assert.Equal(t, 30*time.Second, rc.RequestTimeout)
		assert.Equal(t, def.MaxConcurrentRequests, rc.MaxConcurrentRequests)
		assert.Equal(t, def.FailureThreshold, rc.FailureThreshold)
		assert.Equal(t, def.SuccessThreshold, rc.SuccessThreshold)
		assert.Equal(t, def.CircuitBreakerDelay, rc.CircuitBreakerDelay)
		assert.Equal(t, def.MaxRetries, rc.MaxRetries)
		assert.Equal(t, def.RetryDelay, rc.RetryDelay)
		assert.Equal(t, def.RetryMaxDelay, rc.RetryMaxDelay)
	})

	t.Run("full overrides", func(t *testing.T) {
		in := config.ResilienceConfig{
			MaxRequestsPerSecond:  50,
			MaxConcurrentRequests: 20,
			FailureThreshold:      10,
			SuccessThreshold:      7,
			CircuitBreakerDelay:   common.Duration(5 * time.Second),
			RequestTimeout:        common.Duration(15 * time.Second),
			MaxRetries:            5,
			RetryDelay:            common.Duration(500 * time.Millisecond),
			RetryMaxDelay:         common.Duration(30 * time.Second),
		}
		require.NoError(t, in.Validate())
		rc := NewResilienceConfig(in)
		assert.Equal(t, uint(50), rc.MaxRequestsPerSecond)
		assert.Equal(t, uint(20), rc.MaxConcurrentRequests)
		assert.Equal(t, uint32(10), rc.FailureThreshold)
		assert.Equal(t, uint32(7), rc.SuccessThreshold)
		assert.Equal(t, 5*time.Second, rc.CircuitBreakerDelay)
		assert.Equal(t, 15*time.Second, rc.RequestTimeout)
		assert.Equal(t, 5, rc.MaxRetries)
		assert.Equal(t, 500*time.Millisecond, rc.RetryDelay)
		assert.Equal(t, 30*time.Second, rc.RetryMaxDelay)
	})
}

type mockOffchainReader struct {
	mu           sync.Mutex
	callCount    int
	failuresLeft int
	delay        time.Duration
	responses    []protocol.QueryResponse
}

func (m *mockOffchainReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	m.mu.Lock()
	m.callCount++
	failed := m.failuresLeft > 0
	if failed {
		m.failuresLeft--
	}
	m.mu.Unlock()
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if failed {
		return nil, errors.New("transient downstream error")
	}
	return m.responses, nil
}

func (m *mockOffchainReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	return nil, nil
}

func (m *mockOffchainReader) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func TestResilientReader_RateLimiterWaitsForPermit(t *testing.T) {
	mock := &mockOffchainReader{
		responses: []protocol.QueryResponse{{}},
	}
	lggr, err := logger.New()
	require.NoError(t, err)

	cfg := ResilienceConfig{
		FailureThreshold:      100,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   3 * time.Second,
		RequestTimeout:        10 * time.Second,
		MaxConcurrentRequests: 5,
		MaxRequestsPerSecond:  1,
		MaxRetries:            5,
		RetryDelay:            50 * time.Millisecond,
		RetryMaxDelay:         500 * time.Millisecond,
	}

	rr := NewResilientReader(mock, lggr, cfg)
	ctx := context.Background()

	resp1, err := rr.ReadCCVData(ctx)
	require.NoError(t, err)
	assert.Len(t, resp1, 1)

	start := time.Now()
	resp2, err := rr.ReadCCVData(ctx)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Len(t, resp2, 1)

	assert.Greater(t, elapsed, 500*time.Millisecond,
		"second call should have waited for the rate limiter permit window")
	assert.Equal(t, 2, mock.getCallCount(),
		"both calls should reach downstream after waiting for permits")
}

func TestResilientReader_RetriesDownstreamError(t *testing.T) {
	mock := &mockOffchainReader{
		responses:    []protocol.QueryResponse{{}},
		failuresLeft: 1,
	}
	lggr, err := logger.New()
	require.NoError(t, err)

	cfg := DefaultResilienceConfig()
	cfg.RetryDelay = 10 * time.Millisecond
	cfg.RetryMaxDelay = 50 * time.Millisecond

	rr := NewResilientReader(mock, lggr, cfg)

	resp, err := rr.ReadCCVData(context.Background())
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, 2, mock.getCallCount(),
		"downstream should be attempted twice: one failure then one successful retry")
}

func TestResilientReader_RequestTimeoutExceeded(t *testing.T) {
	mock := &mockOffchainReader{
		responses: []protocol.QueryResponse{{}},
		delay:     time.Second,
	}
	lggr, err := logger.New()
	require.NoError(t, err)

	cfg := DefaultResilienceConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	cfg.MaxRetries = 0

	rr := NewResilientReader(mock, lggr, cfg)

	_, err = rr.ReadCCVData(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, timeout.ErrExceeded,
		"request timeout (50ms) should mark the attempt failed; the 1s call exceeds it")
	assert.Equal(t, 1, mock.getCallCount())
}

// TestResilientReader_RateLimitExceededNotRetriedAndBreakerStaysClosed verifies
// that a rate-limit rejection aborts without retry and never enters the circuit
// breaker. FailureThreshold=1 and CircuitBreakerDelay=10s make this a regression
// test for the policy order: with the old rp, cb, rl stack the single rejection
// is classified as a breaker failure and opens the breaker for the rest of the test.
func TestResilientReader_RateLimitExceededNotRetriedAndBreakerStaysClosed(t *testing.T) {
	mock := &mockOffchainReader{
		responses: []protocol.QueryResponse{{}},
		delay:     1500 * time.Millisecond,
	}
	lggr, err := logger.New()
	require.NoError(t, err)

	cfg := ResilienceConfig{
		FailureThreshold:      1,
		SuccessThreshold:      2,
		CircuitBreakerDelay:   10 * time.Second,
		RequestTimeout:        10 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  1,
		MaxRetries:            3,
		RetryDelay:            50 * time.Millisecond,
		RetryMaxDelay:         100 * time.Millisecond,
	}

	rr := NewResilientReader(mock, lggr, cfg)

	var rateLimitErrors, successes atomic.Int32
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			_, err := rr.ReadCCVData(context.Background())
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ratelimiter.ErrExceeded) {
				rateLimitErrors.Add(1)
			}
		})
	}
	wg.Wait()

	require.Equal(t, int32(1), rateLimitErrors.Load(),
		"exactly one call should get ErrExceeded")
	require.Equal(t, int32(2), successes.Load(),
		"two calls should succeed after waiting for permits")

	assert.Equal(t, 2, mock.getCallCount(),
		"downstream should be called exactly twice; rate-limited call must not retry")

	assert.Equal(t, circuitbreaker.ClosedState, rr.GetDiscoveryCircuitBreakerState(),
		"circuit breaker must remain closed: the rejection never enters the breaker")
}
