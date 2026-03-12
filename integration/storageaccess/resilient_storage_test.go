package storageaccess

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsNetworkOrTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error returns false",
			err:  nil,
			want: false,
		},
		{
			name: "gRPC Unavailable returns true",
			err:  status.Error(codes.Unavailable, "connection unavailable"),
			want: true,
		},
		{
			name: "gRPC DeadlineExceeded returns true",
			err:  status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			want: true,
		},
		{
			name: "gRPC Canceled returns true",
			err:  status.Error(codes.Canceled, "context canceled"),
			want: true,
		},
		{
			name: "gRPC ResourceExhausted returns true",
			err:  status.Error(codes.ResourceExhausted, "service temporarily unavailable"),
			want: true,
		},
		{
			name: "gRPC InvalidArgument returns false",
			err:  status.Error(codes.InvalidArgument, "validation failed: invalid request format"),
			want: false,
		},
		{
			name: "gRPC FailedPrecondition returns false",
			err:  status.Error(codes.FailedPrecondition, "invalid state"),
			want: false,
		},
		{
			name: "plain error with dial tcp returns true",
			err:  errors.New("dial tcp 1.2.3.4:443: connect: connection refused"),
			want: true,
		},
		{
			name: "plain error with connection refused returns true",
			err:  errors.New("connection refused"),
			want: true,
		},
		{
			name: "plain error with i/o timeout returns true",
			err:  errors.New("read: i/o timeout"),
			want: true,
		},
		{
			name: "plain error with validation failed returns false",
			err:  errors.New("validation failed: invalid signature"),
			want: false,
		},
		{
			name: "plain error with no transport keywords returns false",
			err:  errors.New("something else failed"),
			want: false,
		},
		{
			name: "wrapped gRPC Unavailable returns true",
			err:  fmt.Errorf("write: %w", status.Error(codes.Unavailable, "transient failure")),
			want: true,
		},
		{
			name: "wrapped gRPC InvalidArgument returns false",
			err:  fmt.Errorf("batch write: %w", status.Error(codes.InvalidArgument, "invalid request")),
			want: false,
		},
		{
			name: "plain error with connection reset returns true",
			err:  errors.New("connection reset by peer"),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNetworkOrTransportError(tt.err)
			require.Equal(t, tt.want, got, "isNetworkOrTransportError(%v)", tt.err)
		})
	}
}

func TestDefaultHandleIfDoesNotCountInvalidArgumentAsFailure(t *testing.T) {
	config := defaultAggregatorResilienceConfig()
	require.Nil(t, config.CircuitBreakerErrorHandler)
	handleIf := func(_ any, err error) bool { return err != nil && isNetworkOrTransportError(err) }
	validationErr := status.Error(codes.InvalidArgument, "validation failed")
	require.False(t, handleIf(nil, validationErr), "default handleIf must not count InvalidArgument toward circuit breaker")
}
