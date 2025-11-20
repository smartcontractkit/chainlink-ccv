package storageaccess

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

var _ protocol.CCVNodeDataWriter = (*ResilientAggregator)(nil)

// AggregatorResilienceConfig contains configuration for aggregator writer resiliency policies.
type AggregatorResilienceConfig struct {
	CircuitBreakerErrorHandler func(any, error) bool

	FailureThreshold      uint
	SuccessThreshold      uint
	CircuitBreakerDelay   time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint
	WriteTimeout          time.Duration
}

// DefaultAggregatorResilienceConfig returns a configuration with sensible defaults for gRPC aggregator writer.
func DefaultAggregatorResilienceConfig() AggregatorResilienceConfig {
	return AggregatorResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   2 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  10,
		WriteTimeout:          2 * time.Second,
	}
}

// ResilientAggregator decorates protocol.CCVNodeDataWriter
// with failsafe-go policies: circuit breaker, timeout, rate limiter, and bulkhead.
type ResilientAggregator struct {
	writer protocol.CCVNodeDataWriter

	// Shared policies
	circuitBreaker circuitbreaker.CircuitBreaker[any]
	rateLimiter    ratelimiter.RateLimiter[any]
	bulkhead       bulkhead.Bulkhead[any]
	writeTimeout   timeout.Timeout[any]

	lggr                 logger.Logger
	consecutiveErrors    atomic.Int32
	maxConsecutiveErrors int32
}

// NewResilientAggregator creates a new resilient aggregator writer with custom configuration.
func NewResilientAggregator(
	writer protocol.CCVNodeDataWriter,
	lggr logger.Logger,
	config AggregatorResilienceConfig,
) *ResilientAggregator {
	handleIf := func(_ any, err error) bool { return err != nil }
	if config.CircuitBreakerErrorHandler != nil {
		handleIf = config.CircuitBreakerErrorHandler
	}

	cb := circuitbreaker.NewBuilder[any]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(handleIf).
		OnOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Warnw("Aggregator circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Info("Aggregator circuit breaker entering half-open state")
		}).
		OnClose(func(circuitbreaker.StateChangedEvent) {
			lggr.Infow("Aggregator circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(config.FailureThreshold).
		WithSuccessThreshold(config.SuccessThreshold).
		Build()

	rl := ratelimiter.NewBursty[any](config.MaxRequestsPerSecond, time.Second)

	bh := bulkhead.NewBuilder[any](config.MaxConcurrentRequests).
		OnFull(func(failsafe.ExecutionEvent[any]) {
			lggr.Warnw("Aggregator bulkhead is full", "max_concurrent_requests", config.MaxConcurrentRequests)
		}).
		Build()

	writeTO := timeout.NewBuilder[any](config.WriteTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[any]) {
			lggr.Warnw("Aggregator write request timeout exceeded", "timeout", config.WriteTimeout)
		}).
		Build()

	return &ResilientAggregator{
		writer:               writer,
		circuitBreaker:       cb,
		rateLimiter:          rl,
		bulkhead:             bh,
		writeTimeout:         writeTO,
		lggr:                 lggr,
		maxConsecutiveErrors: 10,
	}
}

// NewDefaultResilientAggregator creates a new resilient aggregator writer with sensible defaults.
func NewDefaultResilientAggregator(
	writer protocol.CCVNodeDataWriter,
	lggr logger.Logger,
) *ResilientAggregator {
	return NewResilientAggregator(
		writer,
		lggr,
		DefaultAggregatorResilienceConfig(),
	)
}

// WriteCCVNodeData writes CCV data with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *ResilientAggregator) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.CCVData) error {
	executor := failsafe.With(r.rateLimiter, r.bulkhead, r.circuitBreaker, r.writeTimeout)

	_, err := executor.GetWithExecution(func(failsafe.Execution[any]) (any, error) {
		return nil, r.writer.WriteCCVNodeData(ctx, ccvDataList)
	})
	if err != nil {
		r.recordError()
		if r.circuitBreaker.State() == circuitbreaker.OpenState {
			return fmt.Errorf("circuit breaker is open, aggregator service unavailable: %w", err)
		}
		return fmt.Errorf("failed to write CCV data: %w", err)
	}

	r.recordSuccess()
	return nil
}

// GetCircuitBreakerState returns the current state of the circuit breaker.
func (r *ResilientAggregator) GetCircuitBreakerState() circuitbreaker.State {
	return r.circuitBreaker.State()
}

func (r *ResilientAggregator) recordError() {
	count := r.consecutiveErrors.Add(1)
	if count >= r.maxConsecutiveErrors {
		r.lggr.Warnw("Max consecutive aggregator errors reached", "consecutive_errors", count)
	}
}

func (r *ResilientAggregator) recordSuccess() {
	r.consecutiveErrors.Store(0)
}
