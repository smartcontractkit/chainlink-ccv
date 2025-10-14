package readers

import (
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewAggregatorReader(address string, lggr logger.Logger, since int64) (*ResilientReader, error) {
	reader, err := storageaccess.NewAggregatorReader(address, lggr, since, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator reader: %w", err)
	}

	config := DefaultResilienceConfig()
	config.RetryPolicyErrorHandler = aggregatorRetryPolicyErrorHandler
	config.CircuitBreakerErrorHandler = aggregatorCircuitBreakerErrorHandler

	return NewResilientReader(reader, lggr, config), nil
}

// aggregatorRetryPolicyErrorHandler determines if an error from the aggregator should be retried.
// Connection errors (dial timeouts, i/o timeouts, connection refused) are non-retryable.
func aggregatorRetryPolicyErrorHandler(response []protocol.QueryResponse, err error) bool {
	// Don't retry on no error
	if err == nil {
		return false
	}

	if isNonRetryableError(err) {
		return false
	}

	// Retry on other gRPC errors
	return true
}

// aggregatorCircuitBreakerErrorHandler determines if an error should count towards circuit breaker failures.
// Connection errors should NOT open the circuit breaker since they're expected to be temporary.
func aggregatorCircuitBreakerErrorHandler(response []protocol.QueryResponse, err error) bool {
	if err == nil {
		return false
	}

	// Count connection errors towards circuit breaker
	if isNonRetryableError(err) {
		return true
	}

	// Count all other errors
	return true
}

// isNonRetryableError checks if an error is a connection-related error.
func isNonRetryableError(err error) bool {
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "produced zero addresses") ||
		strings.Contains(errMsg, "dial tcp")
}
