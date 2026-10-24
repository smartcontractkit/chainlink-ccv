package registration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

func TestSaveNodesJSONOperation(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)
	for _, node := range []struct {
		name string
		id   string
		key  byte
	}{
		{name: "z-verifier", id: "node-z", key: 1},
		{name: "a-executor", id: "node-a", key: 2},
	} {
		spec := NodeSpec{Name: node.name, Product: "ccv", Environment: env.Name}
		client.addNode(nodeForSpec(spec, validCSAKey(node.key), node.id))
	}
	client.addNode(nodeForSpec(
		NodeSpec{Name: "other", Product: "other", Environment: "other"},
		validCSAKey(3),
		"node-other",
	))

	report, err := operations.ExecuteOperation(
		env.OperationsBundle,
		SaveNodesJSON,
		SaveNodesJSONDeps{JDClient: client, Domain: d, EnvKey: env.Name},
		operations.EmptyInput{},
		operations.WithForceExecute[operations.EmptyInput, SaveNodesJSONDeps](),
	)
	require.NoError(t, err)
	assert.Equal(t, d.EnvDir(env.Name).NodesFilePath(), report.Output.Path)
	assert.Equal(t, 2, report.Output.NodeCount)

	state := readTestNodesFile(t, report.Output.Path)
	require.Len(t, state.Nodes, 2)
	assert.Equal(t, "z-verifier", state.Nodes["node-z"]["name"])
	assert.Equal(t, "a-executor", state.Nodes["node-a"]["name"])
	info, err := os.Stat(report.Output.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestSaveNodesJSONOperationRefusesEmptySnapshot(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)
	path := d.EnvDir(env.Name).NodesFilePath()
	original := []byte(`{"nodes":{"keep":{"name":"keep"}}}`)
	require.NoError(t, os.WriteFile(path, original, 0o600))

	_, err := operations.ExecuteOperation(
		env.OperationsBundle,
		SaveNodesJSON,
		SaveNodesJSONDeps{JDClient: client, Domain: d, EnvKey: env.Name},
		operations.EmptyInput{},
		operations.WithForceExecute[operations.EmptyInput, SaveNodesJSONDeps](),
	)
	require.ErrorContains(t, err, "refusing to overwrite nodes.json")
	actual, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual)
}
