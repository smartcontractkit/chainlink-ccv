package readers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/bulkhead"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/ratelimiter"
	"github.com/failsafe-go/failsafe-go/retrypolicy"
	"github.com/failsafe-go/failsafe-go/timeout"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure ResilientReader conforms to both interfaces.
var (
	_ protocol.OffchainStorageReader = (*ResilientReader)(nil)
	_ protocol.DisconnectableReader  = (*ResilientReader)(nil)
)

// ResilienceConfig contains configuration for resiliency policies.
type ResilienceConfig struct {
	// Error Handlers
	CircuitBreakerErrorHandler func(response []protocol.QueryResponse, err error) bool // Default: nil
	RetryPolicyErrorHandler    func(response []protocol.QueryResponse, err error) bool // Default: nil

	// Circuit Breaker configuration
	FailureThreshold      uint          // Number of failures before opening circuit (default: 5)
	SuccessThreshold      uint          // Number of successes to close circuit (default: 3)
	CircuitBreakerDelay   time.Duration // Delay before attempting to close circuit (default: 30s)
	CircuitBreakerTimeout time.Duration // Timeout for circuit breaker half-open state (default: 10s)

	// Retry Policy configuration
	MaxRetries        int           // Maximum number of retry attempts (default: 3)
	InitialBackoff    time.Duration // Initial backoff duration (default: 100ms)
	MaxBackoff        time.Duration // Maximum backoff duration (default: 10s)
	BackoffMultiplier float64       // Backoff multiplier for exponential backoff (default: 2.0)
	Jitter            time.Duration // Jitter to add to backoff (default: 50ms)

	// Timeout configuration
	RequestTimeout time.Duration // Timeout for individual requests (default: 30s)

	// Bulkhead configuration
	MaxConcurrentRequests uint // Maximum concurrent requests (default: 10)

	// Rate Limiter configuration
	MaxRequestsPerSecond uint // Maximum requests per second (default: 10)

	AllowDisconnect bool // Allow disconnection from the underlying reader (default: false)
}

// DefaultResilienceConfig returns a configuration with sensible defaults.
func DefaultResilienceConfig() ResilienceConfig {
	return ResilienceConfig{
		CircuitBreakerErrorHandler: nil,
		RetryPolicyErrorHandler:    nil,
		FailureThreshold:           5,
		SuccessThreshold:           3,
		CircuitBreakerDelay:        3 * time.Second,
		CircuitBreakerTimeout:      1 * time.Second,
		MaxRetries:                 3,
		InitialBackoff:             150 * time.Millisecond,
		MaxBackoff:                 5 * time.Second,
		BackoffMultiplier:          2.0,
		Jitter:                     50 * time.Millisecond,
		RequestTimeout:             10 * time.Second,
		MaxConcurrentRequests:      5,
		MaxRequestsPerSecond:       10,
		AllowDisconnect:            false,
	}
}

// ResilientReader wraps any OffchainStorageReader with failsafe policies.
type ResilientReader struct {
	underlying     protocol.OffchainStorageReader
	executor       failsafe.Executor[[]protocol.QueryResponse]
	circuitBreaker circuitbreaker.CircuitBreaker[[]protocol.QueryResponse]
	bulkhead       bulkhead.Bulkhead[[]protocol.QueryResponse]
	rateLimiter    ratelimiter.RateLimiter[[]protocol.QueryResponse]
	retryPolicy    retrypolicy.RetryPolicy[[]protocol.QueryResponse]
	timeoutPolicy  timeout.Timeout[[]protocol.QueryResponse]
	lggr           logger.Logger

	mu                   sync.RWMutex
	allowDisconnect      bool
	disconnectSignal     bool
	consecutiveErrors    int
	maxConsecutiveErrors int
}

// NewResilientReader wraps a reader with resiliency policies.
func NewResilientReader(underlying protocol.OffchainStorageReader, lggr logger.Logger, config ResilienceConfig) *ResilientReader {
	// The resilient reader wraps an underlying offchain storage reader with resiliency policies.
	// To do this, we create a failsafe executor with multiple layers of policies to prevent cascading failures.
	//
	// Each layer has a different purpose and they are daisy chained together.
	// The order matters: outermost to innermost
	// RateLimiter -> Bulkhead -> CircuitBreaker -> Retry -> Timeout
	// This means that if the request fails, the next layer will not be called.

	// Rate limits incoming requests
	rl := createRateLimiter(config)
	// Limits concurrent requests
	bh := createBulkhead(config, lggr)
	// Circuit breaks if too many errors occur, allows the downstream service to recover
	cb := createCircuitBreaker(config, lggr)
	// Retries if the request fails, if the request is determined to be non-retryable, the request will not be retried
	retry := createRetryPolicy(config, lggr)
	// Timeout the underlying request, if the request takes too long, it will be aborted
	timeoutPolicy := createTimeoutPolicy(config, lggr)

	// Build failsafe executor with all policies
	// Order matters: outermost to innermost
	// RateLimiter -> Bulkhead -> CircuitBreaker -> Retry -> Timeout
	executor := failsafe.With(rl, bh, cb, retry, timeoutPolicy)

	return &ResilientReader{
		underlying:           underlying,
		executor:             executor,
		circuitBreaker:       cb,
		bulkhead:             bh,
		rateLimiter:          rl,
		retryPolicy:          retry,
		timeoutPolicy:        timeoutPolicy,
		lggr:                 lggr,
		allowDisconnect:      config.AllowDisconnect,
		maxConsecutiveErrors: 10, // Default max consecutive errors before disconnect
	}
}

// ReadCCVData implements the OffchainStorageReader interface with resilience policies applied.
func (r *ResilientReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	if r.isDisconnected() {
		// Shouldn't be called, but just in case we do, don't call the reader again
		return []protocol.QueryResponse{}, fmt.Errorf("reader is disconnected")
	}

	// Execute with all failsafe policies
	responses, err := r.executor.GetWithExecution(func(exec failsafe.Execution[[]protocol.QueryResponse]) ([]protocol.QueryResponse, error) {
		return r.underlying.ReadCCVData(ctx)
	})
	// If the request fails, record and handle the error
	if err != nil {
		r.recordError()
		return nil, r.handleError(err)
	}

	r.recordSuccess()
	return responses, nil
}

// ShouldDisconnect implements the DisconnectableReader interface.
func (r *ResilientReader) ShouldDisconnect() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// If disconnect is not allowed, return false
	if !r.allowDisconnect {
		return false
	}

	// Check if underlying reader wants to disconnect, if it does this takes priority
	if disconnectable, ok := r.underlying.(protocol.DisconnectableReader); ok {
		if disconnectable.ShouldDisconnect() {
			return true
		}
	}

	// Disconnect if we've hit the max consecutive errors or disconnect signal is set
	return r.disconnectSignal || r.consecutiveErrors >= r.maxConsecutiveErrors
}

// GetCircuitBreakerState returns the current state of the circuit breaker.
func (r *ResilientReader) GetCircuitBreakerState() circuitbreaker.State {
	return r.circuitBreaker.State()
}

// isDisconnected checks if the reader has received a disconnect signal.
func (r *ResilientReader) isDisconnected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.disconnectSignal && r.allowDisconnect
}

// recordError tracks consecutive errors and triggers disconnect if threshold is exceeded.
func (r *ResilientReader) recordError() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.consecutiveErrors++
	if r.consecutiveErrors >= r.maxConsecutiveErrors {
		r.lggr.Warnw("Max consecutive errors reached, signaling disconnect (if applicable)",
			"max_consecutive_errors", r.maxConsecutiveErrors,
			"consecutive_errors", r.consecutiveErrors)

		if r.allowDisconnect {
			r.disconnectSignal = true
		}
	}
}

// recordSuccess resets the consecutive error counter.
func (r *ResilientReader) recordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consecutiveErrors = 0
}

// handleError processes errors and provides context-aware error messages.
func (r *ResilientReader) handleError(err error) error {
	// Check if circuit breaker is open
	if r.circuitBreaker.State() == circuitbreaker.OpenState {
		return fmt.Errorf("circuit breaker is open, downstream service unavailable: %w", err)
	}

	return fmt.Errorf("failed to fetch data: %w", err)
}

// createCircuitBreaker creates a circuit breaker for query responses.
func createCircuitBreaker(config ResilienceConfig, lggr logger.Logger) circuitbreaker.CircuitBreaker[[]protocol.QueryResponse] {
	handleIf := func(response []protocol.QueryResponse, err error) bool {
		// Open circuit on errors
		return err != nil
	}

	if config.CircuitBreakerErrorHandler != nil {
		handleIf = config.CircuitBreakerErrorHandler
	}

	return circuitbreaker.NewBuilder[[]protocol.QueryResponse]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(handleIf).
		OnOpen(func(event circuitbreaker.StateChangedEvent) {
			lggr.Warnw("Circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(event circuitbreaker.StateChangedEvent) {
			lggr.Info("Circuit breaker entering half-open state, attempting recovery")
		}).
		OnClose(func(event circuitbreaker.StateChangedEvent) {
			lggr.Infow("Circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(config.FailureThreshold).
		WithSuccessThreshold(config.SuccessThreshold).
		Build()
}

// createRetryPolicy creates a retry policy for query responses.
func createRetryPolicy(config ResilienceConfig, lggr logger.Logger) retrypolicy.RetryPolicy[[]protocol.QueryResponse] {
	handleIf := func(response []protocol.QueryResponse, err error) bool {
		// Retry on any errors
		return err != nil
	}

	if config.RetryPolicyErrorHandler != nil {
		handleIf = config.RetryPolicyErrorHandler
	}

	return retrypolicy.NewBuilder[[]protocol.QueryResponse]().
		HandleIf(handleIf).
		WithMaxRetries(config.MaxRetries).
		WithBackoff(config.InitialBackoff, config.MaxBackoff).
		WithJitter(config.Jitter).
		OnRetry(func(event failsafe.ExecutionEvent[[]protocol.QueryResponse]) {
			lggr.Debugw("Retrying request", "attempt", event.Attempts(), "error", event.LastError())
		}).
		OnRetriesExceeded(func(event failsafe.ExecutionEvent[[]protocol.QueryResponse]) {
			lggr.Warnw("Max retries exceeded", "max_retries", config.MaxRetries, "error", event.LastError())
		}).
		OnAbort(func(event failsafe.ExecutionEvent[[]protocol.QueryResponse]) {
			lggr.Debugw("Retry aborted due to non-retriable error", "error", event.LastError())
		}).
		Build()
}

// createTimeoutPolicy creates a timeout policy for query responses.
func createTimeoutPolicy(config ResilienceConfig, lggr logger.Logger) timeout.Timeout[[]protocol.QueryResponse] {
	return timeout.NewBuilder[[]protocol.QueryResponse](config.RequestTimeout).
		OnTimeoutExceeded(func(event failsafe.ExecutionDoneEvent[[]protocol.QueryResponse]) {
			lggr.Warnw("Request timeout exceeded", "timeout", config.RequestTimeout)
		}).
		Build()
}

// createBulkhead creates a bulkhead for query responses.
func createBulkhead(config ResilienceConfig, lggr logger.Logger) bulkhead.Bulkhead[[]protocol.QueryResponse] {
	return bulkhead.NewBuilder[[]protocol.QueryResponse](config.MaxConcurrentRequests).
		OnFull(func(event failsafe.ExecutionEvent[[]protocol.QueryResponse]) {
			lggr.Warnw("Bulkhead is full", "max_concurrent_requests", config.MaxConcurrentRequests)
		}).
		Build()
}

// createRateLimiter creates a rate limiter for query responses.
func createRateLimiter(config ResilienceConfig) ratelimiter.RateLimiter[[]protocol.QueryResponse] {
	return ratelimiter.NewBursty[[]protocol.QueryResponse](config.MaxRequestsPerSecond, time.Second)
}
