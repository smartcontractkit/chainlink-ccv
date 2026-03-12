package readers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TestIsConnectionError verifies that connection-related errors and
// specific aggregator errors (e.g. "produced zero addresses") are treated
// as non-retryable while other errors are retryable.
func TestIsConnectionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"produced zero addresses exact", errors.New("produced zero addresses"), true},
		{"produced zero addresses caps", errors.New("Produced Zero Addresses"), true},
		{"dial tcp error", errors.New("dial tcp 127.0.0.1:12345: connect: connection refused"), true},
		{"other grpc error", errors.New("rpc error: code = Unavailable desc = some internal failure"), false},
		{"nil", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isConnectionError(tc.err)
			require.Equal(t, tc.want, got, "isConnectionError(%v)", tc.err)
		})
	}
}

// TestAggregatorRetryPolicyErrorHandler ensures the retry policy treats
// non-retryable errors as not to be retried and other errors as retryable.
func TestAggregatorRetryPolicyErrorHandler(t *testing.T) {
	// nil error should not retry
	require.False(t, aggregatorRetryPolicyErrorHandler(nil, nil), "expected no retry on nil error")

	// nil response should not retry
	// non-retryable (connection) -> should not retry
	nonRetry := errors.New("dial tcp 1.2.3.4:123: connect: connection refused")
	require.True(t, isConnectionError(nonRetry), "sanity: isConnectionError returned true for %v", nonRetry)
	require.False(t, aggregatorRetryPolicyErrorHandler(nil, nonRetry), "expected no retry for non-retryable error: %v", nonRetry)

	// other errors should retry
	other := errors.New("rpc error: code = Unavailable desc = transient grpc error")
	require.True(t, aggregatorRetryPolicyErrorHandler(nil, other), "expected retry for other errors: %v", other)
}

// quick smoke test compile-time: pass a dummy response slice.
func TestHelperCompileWithResponse(t *testing.T) {
	resp := []protocol.QueryResponse{{}}
	_ = aggregatorRetryPolicyErrorHandler(resp, errors.New("dial tcp"))
}
