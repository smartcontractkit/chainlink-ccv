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

var (
	_ protocol.CCVNodeDataWriter     = (*ResilientAggregator)(nil)
	_ protocol.OffchainStorageReader = (*ResilientAggregator)(nil)
)

// AggregatorResilienceConfig contains configuration for aggregator resiliency policies.
// Since both reader and writer communicate with the same server, they share circuit breaker,
// bulkhead, and rate limiter, but have separate timeouts.
type AggregatorResilienceConfig struct {
	CircuitBreakerErrorHandler func(any, error) bool

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

// DefaultAggregatorResilienceConfig returns a configuration with sensible defaults for gRPC aggregator.
func DefaultAggregatorResilienceConfig() AggregatorResilienceConfig {
	return AggregatorResilienceConfig{
		FailureThreshold:      5,
		SuccessThreshold:      3,
		CircuitBreakerDelay:   2 * time.Second,
		MaxConcurrentRequests: 10,
		MaxRequestsPerSecond:  10,
		WriteTimeout:          2 * time.Second,
		ReadTimeout:           5 * time.Second,
	}
}

// ResilientAggregator decorates both protocol.CCVNodeDataWriter and protocol.OffchainStorageReader
// with failsafe-go policies. Since both communicate with the same server, they share circuit breaker,
// rate limiter, and bulkhead, but have separate timeout policies for read vs write operations.
type ResilientAggregator struct {
	writer protocol.CCVNodeDataWriter
	reader protocol.OffchainStorageReader

	// Shared policies
	circuitBreaker circuitbreaker.CircuitBreaker[any]
	rateLimiter    ratelimiter.RateLimiter[any]
	bulkhead       bulkhead.Bulkhead[any]

	// Separate timeout policies for read and write
	writeTimeout timeout.Timeout[any]
	readTimeout  timeout.Timeout[any]

	lggr                 logger.Logger
	consecutiveErrors    atomic.Int32
	maxConsecutiveErrors int32
}

// NewResilientAggregator creates a new resilient aggregator with custom configuration.
func NewResilientAggregator(
	writer protocol.CCVNodeDataWriter,
	reader protocol.OffchainStorageReader,
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

	readTO := timeout.NewBuilder[any](config.ReadTimeout).
		OnTimeoutExceeded(func(failsafe.ExecutionDoneEvent[any]) {
			lggr.Warnw("Aggregator read request timeout exceeded", "timeout", config.ReadTimeout)
		}).
		Build()

	return &ResilientAggregator{
		writer:               writer,
		reader:               reader,
		circuitBreaker:       cb,
		rateLimiter:          rl,
		bulkhead:             bh,
		writeTimeout:         writeTO,
		readTimeout:          readTO,
		lggr:                 lggr,
		maxConsecutiveErrors: 10,
	}
}

// NewDefaultResilientAggregator creates a new resilient aggregator with sensible defaults.
func NewDefaultResilientAggregator(
	writer protocol.CCVNodeDataWriter,
	reader protocol.OffchainStorageReader,
	lggr logger.Logger,
) *ResilientAggregator {
	return NewResilientAggregator(
		writer,
		reader,
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

// ReadCCVData reads CCV data with circuit breaker, timeout, rate limiting, and bulkhead protection.
func (r *ResilientAggregator) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	executor := failsafe.With(r.rateLimiter, r.bulkhead, r.circuitBreaker, r.readTimeout)

	result, err := executor.GetWithExecution(func(failsafe.Execution[any]) (any, error) {
		return r.reader.ReadCCVData(ctx)
	})
	if err != nil {
		r.recordError()
		if r.circuitBreaker.State() == circuitbreaker.OpenState {
			return nil, fmt.Errorf("circuit breaker is open, aggregator service unavailable: %w", err)
		}
		return nil, fmt.Errorf("failed to read CCV data: %w", err)
	}

	r.recordSuccess()
	casted, ok := result.([]protocol.QueryResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected type from ReadCCVData: %T", result)
	}
	return casted, nil
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
