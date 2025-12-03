package storageaccess

import (
	"context"
	"fmt"
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

var _ protocol.ChainStatusManager = (*resilientChainStatusManager)(nil)

// resilientChainStatusManager decorates protocol.ChainStatusManager
// with failsafe-go policies. Since both read and write communicate with the same server,
// they share circuit breaker, rate limiter, and bulkhead, but have separate timeout policies.
type resilientChainStatusManager struct {
	delegate protocol.ChainStatusManager
	lggr     logger.Logger

	// Shared policies
	circuitBreaker circuitbreaker.CircuitBreaker[readResult]
	rateLimiter    ratelimiter.RateLimiter[readResult]
	bulkhead       bulkhead.Bulkhead[readResult]
	retryPolicy    retrypolicy.RetryPolicy[readResult]

	// Separate timeout policies for read and write
	writeTimeout timeout.Timeout[readResult]
	readTimeout  timeout.Timeout[readResult]
}

type readResult map[protocol.ChainSelector]*protocol.ChainStatusInfo

// NewDefaultResilientChainStatusManager creates a new resilient chain status manager with sensible defaults.
func NewDefaultResilientChainStatusManager(
	delegate protocol.ChainStatusManager,
	lggr logger.Logger,
) protocol.ChainStatusManager {
	return NewResilientChainStatusManager(
		delegate,
		lggr,
		defaultChainStatusManagerResilienceConfig(),
	)
}

// NewResilientChainStatusManager creates a new resilient chain status manager with custom configuration.
func NewResilientChainStatusManager(
	delegate protocol.ChainStatusManager,
	lggr logger.Logger,
	config chainStatusManagerResilienceConfig,
) protocol.ChainStatusManager {
	// TODO: Consider making error handler to react only upon network errors.
	handleIf := func(_ readResult, err error) bool { return err != nil }
	if config.CircuitBreakerErrorHandler != nil {
		handleIf = config.CircuitBreakerErrorHandler
	}

	cb := circuitbreaker.NewBuilder[readResult]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(handleIf).
		OnOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Warnw("ChainStatusManager circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Info("ChainStatusManager circuit breaker entering half-open state")
		}).
		OnClose(func(circuitbreaker.StateChangedEvent) {
			lggr.Infow("ChainStatusManager circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(config.FailureThreshold).
		WithSuccessThreshold(config.SuccessThreshold).
		Build()

	rl := ratelimiter.NewBursty[readResult](config.MaxRequestsPerSecond, time.Second)

	bh := bulkhead.NewBuilder[readResult](config.MaxConcurrentRequests).
		OnFull(func(failsafe.ExecutionEvent[readResult]) {
			lggr.Warnw("ChainStatusManager bulkhead is full", "max_concurrent_requests", config.MaxConcurrentRequests)
		}).
		Build()

	writeTimeout := timeout.NewBuilder[readResult](config.WriteTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[readResult]) {
			lggr.Warnw("ChainStatusManager write request timeout exceeded", "timeout", config.WriteTimeout)
		}).
		Build()

	readTimeout := timeout.NewBuilder[readResult](config.ReadTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[readResult]) {
			lggr.Warnw("ChainStatusManager read request timeout exceeded", "timeout", config.ReadTimeout)
		}).
		Build()

	policy := retrypolicy.NewBuilder[readResult]().
		WithMaxAttempts(10).
		WithBackoff(100*time.Millisecond, 1*time.Second).
		Build()

	return &resilientChainStatusManager{
		delegate:       delegate,
		circuitBreaker: cb,
		rateLimiter:    rl,
		bulkhead:       bh,
		retryPolicy:    policy,
		writeTimeout:   writeTimeout,
		readTimeout:    readTimeout,
		lggr:           lggr,
	}
}

// WriteChainStatuses writes chain statuses with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *resilientChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	executor := failsafe.With(r.rateLimiter, r.bulkhead, r.circuitBreaker, r.writeTimeout, r.retryPolicy)

	err := executor.RunWithExecution(func(failsafe.Execution[readResult]) error {
		return r.delegate.WriteChainStatuses(ctx, statuses)
	})
	if err != nil {
		if r.circuitBreaker.State() == circuitbreaker.OpenState {
			return fmt.Errorf("circuit breaker is open, chain status service unavailable: %w", err)
		}
		return fmt.Errorf("failed to write chain statuses: %w", err)
	}

	return nil
}

// ReadChainStatuses reads chain statuses with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *resilientChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	executor := failsafe.With(r.rateLimiter, r.bulkhead, r.circuitBreaker, r.readTimeout, r.retryPolicy)

	result, err := executor.GetWithExecution(func(failsafe.Execution[readResult]) (readResult, error) {
		return r.delegate.ReadChainStatuses(ctx, chainSelectors)
	})
	if err != nil {
		if r.circuitBreaker.State() == circuitbreaker.OpenState {
			return nil, fmt.Errorf("circuit breaker is open, chain status service unavailable: %w", err)
		}
		return nil, fmt.Errorf("failed to read chain statuses: %w", err)
	}
	return result, nil
}

// chainStatusManagerResilienceConfig contains configuration for chain status manager resiliency policies.
// Since both read and write communicate with the same server, they share circuit breaker,
// bulkhead, and rate limiter, but have separate timeouts.
type chainStatusManagerResilienceConfig struct {
	CircuitBreakerErrorHandler func(readResult, error) bool

	// Shared settings
	FailureThreshold      uint
	SuccessThreshold      uint
	CircuitBreakerDelay   time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint

	// Operation-specific timeouts
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

// defaultChainStatusManagerResilienceConfig returns a configuration with sensible defaults for chain status manager.
func defaultChainStatusManagerResilienceConfig() chainStatusManagerResilienceConfig {
	return chainStatusManagerResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   2 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  10,
		WriteTimeout:          2 * time.Second,
		ReadTimeout:           5 * time.Second,
	}
}
