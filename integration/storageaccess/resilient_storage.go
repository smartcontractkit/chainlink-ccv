package storageaccess

import (
	"context"
	"fmt"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/bulkhead"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/ratelimiter"
	"github.com/failsafe-go/failsafe-go/timeout"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*resilientAggregatorWriter)(nil)

// resilientAggregatorWriter decorates protocol.CCVNodeDataWriter
// with failsafe-go policies: circuit breaker, timeout, rate limiter, and bulkhead.
type resilientAggregatorWriter struct {
	writer protocol.CCVNodeDataWriter
	lggr   logger.Logger

	circuitBreaker circuitbreaker.CircuitBreaker[any]
	rateLimiter    ratelimiter.RateLimiter[any]
	bulkhead       bulkhead.Bulkhead[any]
	writeTimeout   timeout.Timeout[any]
}

// NewDefaultResilientStorageWriter creates a new resilient aggregator writer with sensible defaults.
func NewDefaultResilientStorageWriter(
	writer protocol.CCVNodeDataWriter,
	lggr logger.Logger,
) protocol.CCVNodeDataWriter {
	return NewResilientStorageWriter(
		writer,
		lggr,
		defaultAggregatorResilienceConfig(),
	)
}

// NewResilientStorageWriter creates a new resilient aggregator writer with custom configuration.
func NewResilientStorageWriter(
	writer protocol.CCVNodeDataWriter,
	lggr logger.Logger,
	config aggregatorResilienceConfig,
) protocol.CCVNodeDataWriter {
	// TODO: Consider making error handler to react only upon network errors.
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

	writeTimeout := timeout.NewBuilder[any](config.WriteTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[any]) {
			lggr.Warnw("Aggregator write request timeout exceeded", "timeout", config.WriteTimeout)
		}).
		Build()

	return &resilientAggregatorWriter{
		writer:         writer,
		circuitBreaker: cb,
		rateLimiter:    rl,
		bulkhead:       bh,
		writeTimeout:   writeTimeout,
		lggr:           lggr,
	}
}

// WriteCCVNodeData writes CCV data with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *resilientAggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.CCVData) error {
	executor := failsafe.With(r.rateLimiter, r.bulkhead, r.circuitBreaker, r.writeTimeout)

	_, err := executor.GetWithExecution(func(failsafe.Execution[any]) (any, error) {
		return nil, r.writer.WriteCCVNodeData(ctx, ccvDataList)
	})
	if err != nil {
		if r.circuitBreaker.State() == circuitbreaker.OpenState {
			return fmt.Errorf("circuit breaker is open, aggregator service unavailable: %w", err)
		}
		return fmt.Errorf("failed to write CCV data: %w", err)
	}
	return nil
}

// aggregatorResilienceConfig contains configuration for aggregator writer resiliency policies.
type aggregatorResilienceConfig struct {
	CircuitBreakerErrorHandler func(any, error) bool

	FailureThreshold      uint
	SuccessThreshold      uint
	CircuitBreakerDelay   time.Duration
	MaxConcurrentRequests uint
	MaxRequestsPerSecond  uint
	WriteTimeout          time.Duration
}

// defaultAggregatorResilienceConfig returns a configuration with sensible defaults for gRPC aggregator writer.
func defaultAggregatorResilienceConfig() aggregatorResilienceConfig {
	return aggregatorResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   2 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  10,
		WriteTimeout:          2 * time.Second,
	}
}
