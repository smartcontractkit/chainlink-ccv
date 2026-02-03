// Code generated manually for testing. Based on mockery v2 pattern.

package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"

	protocolrpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
)

// MockStellarRPCClient is a mock type for the stellar.RPCClient interface.
type MockStellarRPCClient struct {
	mock.Mock
}

type MockStellarRPCClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockStellarRPCClient) EXPECT() *MockStellarRPCClient_Expecter {
	return &MockStellarRPCClient_Expecter{mock: &_m.Mock}
}

// GetLatestLedger provides a mock function with given fields: ctx
func (_m *MockStellarRPCClient) GetLatestLedger(ctx context.Context) (protocolrpc.GetLatestLedgerResponse, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetLatestLedger")
	}

	var r0 protocolrpc.GetLatestLedgerResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (protocolrpc.GetLatestLedgerResponse, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) protocolrpc.GetLatestLedgerResponse); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(protocolrpc.GetLatestLedgerResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStellarRPCClient_GetLatestLedger_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLatestLedger'
type MockStellarRPCClient_GetLatestLedger_Call struct {
	*mock.Call
}

// GetLatestLedger is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockStellarRPCClient_Expecter) GetLatestLedger(ctx interface{}) *MockStellarRPCClient_GetLatestLedger_Call {
	return &MockStellarRPCClient_GetLatestLedger_Call{Call: _e.mock.On("GetLatestLedger", ctx)}
}

func (_c *MockStellarRPCClient_GetLatestLedger_Call) Run(run func(ctx context.Context)) *MockStellarRPCClient_GetLatestLedger_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockStellarRPCClient_GetLatestLedger_Call) Return(_a0 protocolrpc.GetLatestLedgerResponse, _a1 error) *MockStellarRPCClient_GetLatestLedger_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStellarRPCClient_GetLatestLedger_Call) RunAndReturn(run func(context.Context) (protocolrpc.GetLatestLedgerResponse, error)) *MockStellarRPCClient_GetLatestLedger_Call {
	_c.Call.Return(run)
	return _c
}

// GetLedgers provides a mock function with given fields: ctx, req
func (_m *MockStellarRPCClient) GetLedgers(ctx context.Context, req protocolrpc.GetLedgersRequest) (protocolrpc.GetLedgersResponse, error) {
	ret := _m.Called(ctx, req)

	if len(ret) == 0 {
		panic("no return value specified for GetLedgers")
	}

	var r0 protocolrpc.GetLedgersResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, protocolrpc.GetLedgersRequest) (protocolrpc.GetLedgersResponse, error)); ok {
		return rf(ctx, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, protocolrpc.GetLedgersRequest) protocolrpc.GetLedgersResponse); ok {
		r0 = rf(ctx, req)
	} else {
		r0 = ret.Get(0).(protocolrpc.GetLedgersResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, protocolrpc.GetLedgersRequest) error); ok {
		r1 = rf(ctx, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStellarRPCClient_GetLedgers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLedgers'
type MockStellarRPCClient_GetLedgers_Call struct {
	*mock.Call
}

// GetLedgers is a helper method to define mock.On call
//   - ctx context.Context
//   - req protocolrpc.GetLedgersRequest
func (_e *MockStellarRPCClient_Expecter) GetLedgers(ctx interface{}, req interface{}) *MockStellarRPCClient_GetLedgers_Call {
	return &MockStellarRPCClient_GetLedgers_Call{Call: _e.mock.On("GetLedgers", ctx, req)}
}

func (_c *MockStellarRPCClient_GetLedgers_Call) Run(run func(ctx context.Context, req protocolrpc.GetLedgersRequest)) *MockStellarRPCClient_GetLedgers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(protocolrpc.GetLedgersRequest))
	})
	return _c
}

func (_c *MockStellarRPCClient_GetLedgers_Call) Return(_a0 protocolrpc.GetLedgersResponse, _a1 error) *MockStellarRPCClient_GetLedgers_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStellarRPCClient_GetLedgers_Call) RunAndReturn(run func(context.Context, protocolrpc.GetLedgersRequest) (protocolrpc.GetLedgersResponse, error)) *MockStellarRPCClient_GetLedgers_Call {
	_c.Call.Return(run)
	return _c
}

// GetEvents provides a mock function with given fields: ctx, req
func (_m *MockStellarRPCClient) GetEvents(ctx context.Context, req protocolrpc.GetEventsRequest) (protocolrpc.GetEventsResponse, error) {
	ret := _m.Called(ctx, req)

	if len(ret) == 0 {
		panic("no return value specified for GetEvents")
	}

	var r0 protocolrpc.GetEventsResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, protocolrpc.GetEventsRequest) (protocolrpc.GetEventsResponse, error)); ok {
		return rf(ctx, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, protocolrpc.GetEventsRequest) protocolrpc.GetEventsResponse); ok {
		r0 = rf(ctx, req)
	} else {
		r0 = ret.Get(0).(protocolrpc.GetEventsResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, protocolrpc.GetEventsRequest) error); ok {
		r1 = rf(ctx, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStellarRPCClient_GetEvents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetEvents'
type MockStellarRPCClient_GetEvents_Call struct {
	*mock.Call
}

// GetEvents is a helper method to define mock.On call
//   - ctx context.Context
//   - req protocolrpc.GetEventsRequest
func (_e *MockStellarRPCClient_Expecter) GetEvents(ctx interface{}, req interface{}) *MockStellarRPCClient_GetEvents_Call {
	return &MockStellarRPCClient_GetEvents_Call{Call: _e.mock.On("GetEvents", ctx, req)}
}

func (_c *MockStellarRPCClient_GetEvents_Call) Run(run func(ctx context.Context, req protocolrpc.GetEventsRequest)) *MockStellarRPCClient_GetEvents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(protocolrpc.GetEventsRequest))
	})
	return _c
}

func (_c *MockStellarRPCClient_GetEvents_Call) Return(_a0 protocolrpc.GetEventsResponse, _a1 error) *MockStellarRPCClient_GetEvents_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStellarRPCClient_GetEvents_Call) RunAndReturn(run func(context.Context, protocolrpc.GetEventsRequest) (protocolrpc.GetEventsResponse, error)) *MockStellarRPCClient_GetEvents_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockStellarRPCClient creates a new instance of MockStellarRPCClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockStellarRPCClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockStellarRPCClient {
	mock := &MockStellarRPCClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
