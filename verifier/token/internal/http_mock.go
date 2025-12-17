package internal

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/http"
)

// MockHTTPClient is a mock implementation of httputil.Client.
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Get(ctx context.Context, path string) (protocol.ByteSlice, http.Status, error) {
	args := m.Called(ctx, path)
	//nolint
	return args.Get(0).(protocol.ByteSlice), args.Get(1).(http.Status), args.Error(2)
}

func (m *MockHTTPClient) Post(
	ctx context.Context, path string, requestData protocol.ByteSlice,
) (protocol.ByteSlice, http.Status, error) {
	args := m.Called(ctx, path, requestData)
	//nolint
	return args.Get(0).(protocol.ByteSlice), args.Get(1).(http.Status), args.Error(2)
}
