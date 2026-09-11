package readers

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/bulkhead"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/ratelimiter"
	"github.com/failsafe-go/failsafe-go/retrypolicy"
	"github.com/failsafe-go/failsafe-go/timeout"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var (
	_ protocol.OffchainStorageReader = (*ResilientReader)(nil)
	_ protocol.VerifierResultsAPI    = (*ResilientReader)(nil)
)

// ResilienceConfig contains configuration for resiliency policies.
type ResilienceConfig struct {
	CircuitBreakerErrorHandler func(map[protocol.Bytes32]protocol.VerifierResult, error) bool
	RetryPolicyErrorHandler    func(map[protocol.Bytes32]protocol.VerifierResult, error) bool

	DiscoveryCircuitBreakerErrorHandler func([]protocol.QueryResponse, error) bool
	DiscoveryRetryPolicyErrorHandler    func([]protocol.QueryResponse, error) bool

	// Shared configuration
	FailureThreshold      uint32
	SuccessThreshold      uint32
	CircuitBreakerDelay   time.Duration
	CircuitBreakerTimeout time.Duration
	RequestTimeout        time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint
	MaxRetries            int
	RetryDelay            time.Duration
	RetryMaxDelay         time.Duration
}

// DefaultResilienceConfig returns a configuration with sensible defaults.
func DefaultResilienceConfig() ResilienceConfig {
	return ResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   3 * time.Second,
		CircuitBreakerTimeout: 1 * time.Second,
		RequestTimeout:        10 * time.Second,
		MaxConcurrentRequests: 5,
		MaxRequestsPerSecond:  5,
		MaxRetries:            3,
		RetryDelay:            1 * time.Second,
		RetryMaxDelay:         10 * time.Second,
	}
}

// NewResilienceConfig builds a readers.ResilienceConfig from the indexer's
// config.ResilienceConfig, applying defaults for any zero-value fields.
func NewResilienceConfig(c config.ResilienceConfig) ResilienceConfig {
	rc := DefaultResilienceConfig()
	if c.MaxRequestsPerSecond > 0 {
		rc.MaxRequestsPerSecond = c.MaxRequestsPerSecond
	}
	if c.MaxConcurrentRequests > 0 {
		rc.MaxConcurrentRequests = c.MaxConcurrentRequests
	}
	if c.FailureThreshold > 0 {
		rc.FailureThreshold = c.FailureThreshold
	}
	if c.SuccessThreshold > 0 {
		rc.SuccessThreshold = c.SuccessThreshold
	}
	if c.CircuitBreakerDelay > 0 {
		rc.CircuitBreakerDelay = time.Duration(c.CircuitBreakerDelay)
	}
	if c.CircuitBreakerTimeout > 0 {
		rc.CircuitBreakerTimeout = time.Duration(c.CircuitBreakerTimeout)
	}
	if c.RequestTimeout > 0 {
		rc.RequestTimeout = time.Duration(c.RequestTimeout)
	}
	if c.MaxRetries > 0 {
		rc.MaxRetries = c.MaxRetries
	}
	if c.RetryDelay > 0 {
		rc.RetryDelay = time.Duration(c.RetryDelay)
	}
	if c.RetryMaxDelay > 0 {
		rc.RetryMaxDelay = time.Duration(c.RetryMaxDelay)
	}
	return rc
}

type executorPolicies[T any] struct {
	executor       failsafe.Executor[T]
	circuitBreaker circuitbreaker.CircuitBreaker[T]
}

// ResilientReader wraps any OffchainStorageReader with failsafe policies.
type ResilientReader struct {
	underlying   protocol.VerifierResultsAPI
	discoveryAPI protocol.OffchainStorageReader

	discoveryPolicies     executorPolicies[[]protocol.QueryResponse]
	verificationsPolicies executorPolicies[map[protocol.Bytes32]protocol.VerifierResult]

	lggr                 logger.Logger
	consecutiveErrors    atomic.Uint32
	maxConsecutiveErrors uint32
}

// NewResilientReader wraps a reader with resiliency policies.
func NewResilientReader(underlying protocol.VerifierResultsAPI, lggr logger.Logger, config ResilienceConfig) *ResilientReader {
	rr := &ResilientReader{
		underlying:           underlying,
		lggr:                 lggr,
		maxConsecutiveErrors: config.FailureThreshold,
	}

	rr.verificationsPolicies = createPolicies(config, lggr, "GetVerifications", config.RetryPolicyErrorHandler, config.CircuitBreakerErrorHandler)

	if discoveryAPI, ok := underlying.(protocol.OffchainStorageReader); ok {
		rr.discoveryPolicies = createPolicies(config, lggr, "ReadCCVData", config.DiscoveryRetryPolicyErrorHandler, config.DiscoveryCircuitBreakerErrorHandler)
		rr.discoveryAPI = discoveryAPI
	}

	return rr
}

func createPolicies[T any](config ResilienceConfig, lggr logger.Logger, name string, retryErrorHandler, cbErrorHandler func(T, error) bool) executorPolicies[T] {
	retryHandleIf := func(resp T, err error) bool { return err != nil }
	if retryErrorHandler != nil {
		retryHandleIf = retryErrorHandler
	}

	rp := retrypolicy.NewBuilder[T]().
		HandleIf(retryHandleIf).
		WithMaxRetries(config.MaxRetries).
		WithBackoff(config.RetryDelay, config.RetryMaxDelay).
		AbortOnErrors(context.Canceled, context.DeadlineExceeded, circuitbreaker.ErrOpen).
		ReturnLastFailure().
		OnRetry(func(failsafe.ExecutionEvent[T]) {
			lggr.Warnw(name+" retrying request", "max_retries", config.MaxRetries)
		}).
		Build()

	cbHandleIf := func(resp T, err error) bool { return err != nil }
	if cbErrorHandler != nil {
		cbHandleIf = cbErrorHandler
	}

	cb := circuitbreaker.NewBuilder[T]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(cbHandleIf).
		OnOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Warnw(name+" circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Info(name + " circuit breaker entering half-open state")
		}).
		OnClose(func(circuitbreaker.StateChangedEvent) {
			lggr.Infow(name+" circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(uint(config.FailureThreshold)).
		WithSuccessThreshold(uint(config.SuccessThreshold)).
		Build()

	rl := ratelimiter.NewBurstyBuilder[T](config.MaxRequestsPerSecond, time.Second).
		WithMaxWaitTime(time.Second). // Wait up to 1 second for a permit before returning ErrExceeded
		Build()
	bh := bulkhead.NewBuilder[T](config.MaxConcurrentRequests).
		OnFull(func(failsafe.ExecutionEvent[T]) {
			lggr.Warnw(name+" bulkhead is full", "max_concurrent_requests", config.MaxConcurrentRequests)
		}).
		Build()
	to := timeout.NewBuilder[T](config.RequestTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[T]) {
			lggr.Warnw(name+" request timeout exceeded", "timeout", config.RequestTimeout)
		}).
		Build()

	return executorPolicies[T]{
		executor:       failsafe.With(rp, cb, rl, bh, to),
		circuitBreaker: cb,
	}
}

func (r *ResilientReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	return execute(ctx, r, r.discoveryPolicies, func() ([]protocol.QueryResponse, error) {
		return r.discoveryAPI.ReadCCVData(ctx)
	})
}

func (r *ResilientReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	return execute(ctx, r, r.verificationsPolicies, func() (map[protocol.Bytes32]protocol.VerifierResult, error) {
		return r.underlying.GetVerifications(ctx, messageIDs)
	})
}

func execute[T any](ctx context.Context, r *ResilientReader, policies executorPolicies[T], fn func() (T, error)) (T, error) {
	result, err := policies.executor.WithContext(ctx).GetWithExecution(func(failsafe.Execution[T]) (T, error) {
		return fn()
	})
	if err != nil {
		r.recordError()
		if policies.circuitBreaker.State() == circuitbreaker.OpenState {
			return result, fmt.Errorf("circuit breaker is open, downstream service unavailable: %w", err)
		}
		return result, fmt.Errorf("failed to fetch data: %w", err)
	}
	r.recordSuccess()
	return result, nil
}

func (r *ResilientReader) GetCircuitBreakerState() circuitbreaker.State {
	return r.verificationsPolicies.circuitBreaker.State()
}

func (r *ResilientReader) GetDiscoveryCircuitBreakerState() circuitbreaker.State {
	return r.discoveryPolicies.circuitBreaker.State()
}

func (r *ResilientReader) recordError() {
	count := r.consecutiveErrors.Add(1)
	if count == r.maxConsecutiveErrors {
		r.lggr.Warnw("Max consecutive read errors reached", "consecutive_errors", count)
	}
}

func (r *ResilientReader) recordSuccess() {
	r.consecutiveErrors.Store(0)
}

// GetSinceValue returns the latest sequence number if the underlying reader supports it.
func (r *ResilientReader) GetSinceValue() (int64, bool) {
	if discoveryReader, ok := r.discoveryAPI.(protocol.DiscoveryStorageReader); ok {
		return discoveryReader.GetSinceValue(), true
	}
	return 0, false
}

func (r *ResilientReader) SetSinceValue(since int64) bool {
	if discoveryReader, ok := r.discoveryAPI.(protocol.DiscoveryStorageReader); ok {
		discoveryReader.SetSinceValue(since)
		return true
	}
	return false
}
