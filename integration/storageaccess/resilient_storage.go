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

var _ protocol.CCVNodeDataWriter = (*ResilientAggregatorWriter)(nil)

type WriterResilienceConfig struct {
	CircuitBreakerErrorHandler func(any, error) bool

	FailureThreshold      uint
	SuccessThreshold      uint
	CircuitBreakerDelay   time.Duration
	RequestTimeout        time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint
}

// DefaultWriterResilienceConfig returns a configuration with sensible defaults for gRPC writer.
func DefaultWriterResilienceConfig() WriterResilienceConfig {
	return WriterResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   2 * time.Second,
		RequestTimeout:        5 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  10,
	}
}

// ResilientAggregatorWriter decorates a protocol.CCVNodeDataWriter
// with failsafe-go policies: circuit breaker, timeout, rate limiter, and bulkhead.
type ResilientAggregatorWriter struct {
	delegate protocol.CCVNodeDataWriter
	executor failsafe.Executor[any]
	breaker  circuitbreaker.CircuitBreaker[any]

	lggr                 logger.Logger
	consecutiveErrors    atomic.Int32
	maxConsecutiveErrors int32
}

// NewResilientAggregatorWriter creates a new resilient writer with custom configuration.
func NewResilientAggregatorWriter(
	delegate protocol.CCVNodeDataWriter,
	lggr logger.Logger,
	config WriterResilienceConfig,
) *ResilientAggregatorWriter {
	handleIf := func(_ any, err error) bool { return err != nil }
	if config.CircuitBreakerErrorHandler != nil {
		handleIf = config.CircuitBreakerErrorHandler
	}

	cb := circuitbreaker.NewBuilder[any]().
		WithDelay(config.CircuitBreakerDelay).
		HandleIf(handleIf).
		OnOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Warnw("WriteCCVNodeData circuit breaker opened", "failures", config.FailureThreshold)
		}).
		OnHalfOpen(func(circuitbreaker.StateChangedEvent) {
			lggr.Info("WriteCCVNodeData circuit breaker entering half-open state")
		}).
		OnClose(func(circuitbreaker.StateChangedEvent) {
			lggr.Infow("WriteCCVNodeData circuit breaker closed", "successes", config.SuccessThreshold)
		}).
		WithFailureThreshold(config.FailureThreshold).
		WithSuccessThreshold(config.SuccessThreshold).
		Build()

	rl := ratelimiter.NewBursty[any](config.MaxRequestsPerSecond, time.Second)

	bh := bulkhead.NewBuilder[any](config.MaxConcurrentRequests).
		OnFull(func(failsafe.ExecutionEvent[any]) {
			lggr.Warnw("WriteCCVNodeData bulkhead is full", "max_concurrent_requests", config.MaxConcurrentRequests)
		}).
		Build()

	to := timeout.NewBuilder[any](config.RequestTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[any]) {
			lggr.Warnw("WriteCCVNodeData request timeout exceeded", "timeout", config.RequestTimeout)
		}).
		Build()

	return &ResilientAggregatorWriter{
		delegate:             delegate,
		executor:             failsafe.With(rl, bh, cb, to),
		breaker:              cb,
		lggr:                 lggr,
		maxConsecutiveErrors: 10,
	}
}

// NewDefaultResilientAggregatorWriter creates a new resilient writer with sensible defaults.
func NewDefaultResilientAggregatorWriter(
	delegate protocol.CCVNodeDataWriter,
	lggr logger.Logger,
) *ResilientAggregatorWriter {
	return NewResilientAggregatorWriter(
		delegate,
		lggr,
		DefaultWriterResilienceConfig(),
	)
}

// WriteCCVNodeData writes CCV data with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *ResilientAggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.CCVData) error {
	_, err := r.executor.GetWithExecution(func(failsafe.Execution[any]) (any, error) {
		return nil, r.delegate.WriteCCVNodeData(ctx, ccvDataList)
	})
	if err != nil {
		r.recordError()
		if r.breaker.State() == circuitbreaker.OpenState {
			return fmt.Errorf("circuit breaker is open, aggregator service unavailable: %w", err)
		}
		return fmt.Errorf("failed to write CCV data: %w", err)
	}

	r.recordSuccess()
	return nil
}

// GetCircuitBreakerState returns the current state of the circuit breaker.
func (r *ResilientAggregatorWriter) GetCircuitBreakerState() circuitbreaker.State {
	return r.breaker.State()
}

func (r *ResilientAggregatorWriter) recordError() {
	count := r.consecutiveErrors.Add(1)
	if count >= r.maxConsecutiveErrors {
		r.lggr.Warnw("Max consecutive write errors reached", "consecutive_errors", count)
	}
}

func (r *ResilientAggregatorWriter) recordSuccess() {
	r.consecutiveErrors.Store(0)
}
