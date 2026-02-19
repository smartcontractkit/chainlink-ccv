package readers

import (
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewAggregatorReader(address string, lggr logger.Logger, since int64, hmacConfig hmac.ClientConfig, insecure bool) (*ResilientReader, error) {
	reader, err := storageaccess.NewAggregatorReader(address, lggr, since, &hmacConfig, insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator reader: %w", err)
	}

	config := DefaultResilienceConfig()
	config.DiscoveryRetryPolicyErrorHandler = aggregatorRetryPolicyErrorHandler
	config.DiscoveryCircuitBreakerErrorHandler = aggregatorRetryPolicyErrorHandler

	return NewResilientReader(reader, lggr, config), nil
}

// aggregatorRetryPolicyErrorHandler determines if an error from the aggregator should be retried.
// Connection errors (dial timeouts, i/o timeouts, connection refused) are non-retryable.
func aggregatorRetryPolicyErrorHandler(response []protocol.QueryResponse, err error) bool {
	// Don't retry on no error
	if err == nil {
		return false
	}

	if isConnectionError(err) {
		return false
	}

	// Retry on other gRPC errors
	return true
}

// isConnectionError checks if an error is a connection-related error.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "produced zero addresses") ||
		strings.Contains(errMsg, "dial tcp")
}
