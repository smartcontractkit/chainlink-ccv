package readers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewResilienceConfig(t *testing.T) {
	def := DefaultResilienceConfig()

	t.Run("zero config returns all defaults", func(t *testing.T) {
		rc := NewResilienceConfig(config.ResilienceConfig{})
		assert.Equal(t, def, rc)
	})

	t.Run("partial overrides keep defaults for unset fields", func(t *testing.T) {
		rc := NewResilienceConfig(config.ResilienceConfig{
			MaxRequestsPerSecond: 100,
			RequestTimeout:       common.Duration(30 * time.Second),
		})
		assert.Equal(t, uint(100), rc.MaxRequestsPerSecond)
		assert.Equal(t, 30*time.Second, rc.RequestTimeout)
		assert.Equal(t, def.MaxConcurrentRequests, rc.MaxConcurrentRequests)
		assert.Equal(t, def.FailureThreshold, rc.FailureThreshold)
		assert.Equal(t, def.SuccessThreshold, rc.SuccessThreshold)
		assert.Equal(t, def.CircuitBreakerDelay, rc.CircuitBreakerDelay)
		assert.Equal(t, def.CircuitBreakerTimeout, rc.CircuitBreakerTimeout)
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
			CircuitBreakerTimeout: common.Duration(2 * time.Second),
			RequestTimeout:        common.Duration(15 * time.Second),
			MaxRetries:            5,
			RetryDelay:            common.Duration(500 * time.Millisecond),
			RetryMaxDelay:         common.Duration(30 * time.Second),
		}
		rc := NewResilienceConfig(in)
		assert.Equal(t, uint(50), rc.MaxRequestsPerSecond)
		assert.Equal(t, uint(20), rc.MaxConcurrentRequests)
		assert.Equal(t, uint32(10), rc.FailureThreshold)
		assert.Equal(t, uint32(7), rc.SuccessThreshold)
		assert.Equal(t, 5*time.Second, rc.CircuitBreakerDelay)
		assert.Equal(t, 2*time.Second, rc.CircuitBreakerTimeout)
		assert.Equal(t, 15*time.Second, rc.RequestTimeout)
		assert.Equal(t, 5, rc.MaxRetries)
		assert.Equal(t, 500*time.Millisecond, rc.RetryDelay)
		assert.Equal(t, 30*time.Second, rc.RetryMaxDelay)
	})
}

type mockOffchainReader struct {
	mu        sync.Mutex
	callCount int
	responses []protocol.QueryResponse
}

func (m *mockOffchainReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
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

func TestResilientReader_RetryOnRateLimit(t *testing.T) {
	mock := &mockOffchainReader{
		responses: []protocol.QueryResponse{{}},
	}
	lggr, err := logger.New()
	require.NoError(t, err)

	cfg := ResilienceConfig{
		FailureThreshold:      100,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   3 * time.Second,
		CircuitBreakerTimeout: 1 * time.Second,
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
		"second call should have waited for rate limit window reset via retries")
	assert.Equal(t, 2, mock.getCallCount(),
		"mock should be called twice — rate-limited attempts don't reach downstream")
}
