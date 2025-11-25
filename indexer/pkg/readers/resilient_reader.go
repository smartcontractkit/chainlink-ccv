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
	"github.com/failsafe-go/failsafe-go/timeout"

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
	FailureThreshold      uint
	SuccessThreshold      uint
	CircuitBreakerDelay   time.Duration
	CircuitBreakerTimeout time.Duration
	RequestTimeout        time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint
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
	}
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
	consecutiveErrors    atomic.Int32
	maxConsecutiveErrors int32
}

// NewResilientReader wraps a reader with resiliency policies.
func NewResilientReader(underlying protocol.VerifierResultsAPI, lggr logger.Logger, config ResilienceConfig) *ResilientReader {
	rr := &ResilientReader{
		underlying:           underlying,
		lggr:                 lggr,
		maxConsecutiveErrors: 10,
	}

	rr.verificationsPolicies = createPolicies(config, lggr, "GetVerifications", config.CircuitBreakerErrorHandler)

	if discoveryAPI, ok := underlying.(protocol.OffchainStorageReader); ok {
		rr.discoveryPolicies = createPolicies(config, lggr, "ReadCCVData", config.DiscoveryCircuitBreakerErrorHandler)
		rr.discoveryAPI = discoveryAPI
	}

	return rr
}

func createPolicies[T any](config ResilienceConfig, lggr logger.Logger, name string, errorHandler func(T, error) bool) executorPolicies[T] {
	handleIf := func(resp T, err error) bool { return err != nil }
	if errorHandler != nil {
		handleIf = errorHandler
	}

	cb := circuitbreaker.NewBuilder[T]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(handleIf).
		OnOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Warnw(name+" circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Info(name + " circuit breaker entering half-open state")
		}).
		OnClose(func(circuitbreaker.StateChangedEvent) {
			lggr.Infow(name+" circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(config.FailureThreshold).
		WithSuccessThreshold(config.SuccessThreshold).
		Build()

	rl := ratelimiter.NewBursty[T](config.MaxRequestsPerSecond, time.Second)
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
		executor:       failsafe.With(rl, bh, cb, to),
		circuitBreaker: cb,
	}
}

func (r *ResilientReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	return execute(r, r.discoveryPolicies, func() ([]protocol.QueryResponse, error) {
		return r.discoveryAPI.ReadCCVData(ctx)
	})
}

func (r *ResilientReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	return execute(r, r.verificationsPolicies, func() (map[protocol.Bytes32]protocol.VerifierResult, error) {
		return r.underlying.GetVerifications(ctx, messageIDs)
	})
}

func execute[T any](r *ResilientReader, policies executorPolicies[T], fn func() (T, error)) (T, error) {
	result, err := policies.executor.GetWithExecution(func(failsafe.Execution[T]) (T, error) {
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
	if count >= r.maxConsecutiveErrors {
		r.lggr.Warnw("Max consecutive write errors reached", "consecutive_errors", count)
	}
}

func (r *ResilientReader) recordSuccess() {
	r.consecutiveErrors.Store(0)
}
