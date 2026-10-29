package registration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

func TestRegisterNodeWithJDOperation(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)
	deps := RegisterNodeDeps{JDClient: client, Domain: d, EnvKey: env.Name}
	register := func(input RegisterNodeInput) RegisterNodeOutput {
		report, err := operations.ExecuteOperation(
			env.OperationsBundle,
			RegisterNodeWithJD,
			deps,
			input,
			operations.WithForceExecute[RegisterNodeInput, RegisterNodeDeps](),
		)
		require.NoError(t, err)
		return report.Output
	}

	pluginInput := RegisterNodeInput{
		Name: "verifier", CSAKey: validCSAKey(1), Labels: map[string]string{"role": "verifier"},
	}
	plugin := register(pluginInput)
	require.True(t, plugin.WasRegistered)
	require.NotEmpty(t, plugin.NodeID)

	bootstrap := register(RegisterNodeInput{
		Name: "bootstrap", CSAKey: validCSAKey(2), IsBootstrap: true, Labels: map[string]string{"role": "bootstrap"},
	})
	require.True(t, bootstrap.WasRegistered)
	require.NotEqual(t, plugin.NodeID, bootstrap.NodeID)

	existing := register(pluginInput)
	assert.False(t, existing.WasRegistered)
	assert.Equal(t, plugin.NodeID, existing.NodeID)
	require.Len(t, client.snapshotNodes(), 2)

	nodes := client.snapshotNodes()
	pluginLabels := labelMap(nodes[plugin.NodeID].Labels)
	assert.Equal(t, "ccv", pluginLabels["product"])
	assert.Equal(t, "test", pluginLabels["environment"])
	assert.Equal(t, "plugin", pluginLabels["type"])
	assert.Equal(t, "verifier", pluginLabels["role"])
	bootstrapLabels := labelMap(nodes[bootstrap.NodeID].Labels)
	assert.Equal(t, "bootstrap", bootstrapLabels["type"])
	assert.Equal(t, "bootstrap", bootstrapLabels["role"])
}

func TestRegisterNodeWithJDOperationLookupFailure(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		return nil, status.Error(codes.Unavailable, "JD unavailable")
	}
	registerCalled := false
	client.registerFunc = func(context.Context, *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
		registerCalled = true
		return nil, nil
	}
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)

	_, err := operations.ExecuteOperation(
		env.OperationsBundle,
		RegisterNodeWithJD,
		RegisterNodeDeps{JDClient: client, Domain: d, EnvKey: env.Name},
		RegisterNodeInput{Name: "verifier", CSAKey: validCSAKey(1)},
		operations.WithForceExecute[RegisterNodeInput, RegisterNodeDeps](),
	)
	require.ErrorContains(t, err, "look up node verifier by CSA key")
	assert.False(t, registerCalled)
}

func TestIsJDNotFoundCompatibility(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "direct", err: status.Error(codes.NotFound, "missing"), want: true},
		{name: "wrapped", err: fmt.Errorf("lookup: %w", status.Error(codes.NotFound, "missing")), want: true},
		{name: "production wrapped", err: status.Error(codes.Internal, "rpc error: code = NotFound desc = missing"), want: true},
		{name: "other internal", err: status.Error(codes.Internal, "connection refused"), want: false},
		{name: "other code", err: status.Error(codes.Unauthenticated, "denied"), want: false},
		{name: "plain error", err: errors.New("missing"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsJDNotFound(tt.err))
		})
	}
}
