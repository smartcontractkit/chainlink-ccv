package registration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCsRegisterNodesWithJDPreconditions(t *testing.T) {
	t.Parallel()
	validNode := NodeToRegisterJD{Name: "verifier", CSAKey: validCSAKey(1)}
	secondNode := NodeToRegisterJD{Name: "executor", CSAKey: validCSAKey(2)}
	tests := []struct {
		name    string
		input   CsRegisterNodesWithJDInput
		wantErr string
	}{
		{name: "valid", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{validNode}}},
		{name: "domain required", input: CsRegisterNodesWithJDInput{Nodes: []NodeToRegisterJD{validNode}}, wantErr: "domain is required"},
		{name: "nodes required", input: CsRegisterNodesWithJDInput{Domain: "ccv"}, wantErr: "no nodes provided in input"},
		{name: "name required", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{{CSAKey: validCSAKey(1)}}}, wantErr: "node name cannot be empty"},
		{name: "key required", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{{Name: "verifier"}}}, wantErr: "node CSA key cannot be empty for node verifier"},
		{name: "duplicate name", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{validNode, {Name: "verifier", CSAKey: validCSAKey(2)}}}, wantErr: "duplicate node name in input: verifier"},
		{name: "duplicate key", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{validNode, {Name: "executor", CSAKey: validCSAKey(1)}}}, wantErr: "duplicate csa_key in input for node executor"},
		{name: "valid batch", input: CsRegisterNodesWithJDInput{Domain: "ccv", Nodes: []NodeToRegisterJD{validNode, secondNode}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := (CsRegisterNodesWithJD{}).VerifyPreconditions(newRegistrationTestEnvironment(t, newFakeJD(), "test"), tt.input)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCsRegisterNodesWithJDBatchAndSave(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)
	client.addNode(nodeForSpec(
		NodeSpec{Name: "existing", Product: "ccv", Environment: env.Name},
		validCSAKey(3),
		"node-existing",
	))
	cs := CsRegisterNodesWithJD{Domain: &d}
	input := CsRegisterNodesWithJDInput{
		Domain: "ccv",
		Nodes: []NodeToRegisterJD{
			{Name: "verifier", CSAKey: validCSAKey(1), Labels: map[string]string{"role": "verifier"}},
			{Name: "bootstrap", CSAKey: validCSAKey(2), IsBootstrap: true},
		},
	}
	require.NoError(t, cs.VerifyPreconditions(env, input))
	_, err := cs.Apply(env, input)
	require.NoError(t, err)
	require.Len(t, client.snapshotNodes(), 3)
	assert.Equal(t, 2, client.registerCalls)

	path := d.EnvDir(env.Name).NodesFilePath()
	state := readTestNodesFile(t, path)
	require.Len(t, state.Nodes, 3)
	assert.Equal(t, "existing", state.Nodes["node-existing"]["name"])
	firstState, err := os.ReadFile(path)
	require.NoError(t, err)

	_, err = cs.Apply(env, input)
	require.NoError(t, err)
	assert.Equal(t, 2, client.mutationCount())
	secondState, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, firstState, secondState)

	input.Nodes[0].Labels["role"] = "reconciled"
	_, err = cs.Apply(env, input)
	require.NoError(t, err)
	assert.Equal(t, 3, client.mutationCount())
	verifierFound := false
	for _, node := range client.snapshotNodes() {
		if node.Name == "verifier" {
			verifierFound = true
			assert.Equal(t, "reconciled", labelMap(node.Labels)["role"])
		}
	}
	require.True(t, verifierFound)
	reconciledState, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, secondState, reconciledState)

	_, err = (CsSaveNodesWithJD{Domain: &d}).Apply(env, CsSaveNodesWithJDInput{Domain: "ccv"})
	require.NoError(t, err)
	standaloneState, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, secondState, standaloneState)
}

func TestCsRegisterNodesWithJDFailureSkipsSaveAndContinues(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	env := newRegistrationTestEnvironment(t, client, "test")
	d := newRegistrationTestDomain(t, "ccv", env.Name)
	path := d.EnvDir(env.Name).NodesFilePath()
	original := []byte(`{"nodes":{"keep":{"name":"keep"}}}`)
	require.NoError(t, os.WriteFile(path, original, 0o600))
	cs := CsRegisterNodesWithJD{Domain: &d}
	input := CsRegisterNodesWithJDInput{
		Domain: "ccv",
		Nodes: []NodeToRegisterJD{
			{Name: "first", CSAKey: validCSAKey(1)},
			{Name: "invalid", CSAKey: "not-hex"},
			{Name: "last", CSAKey: validCSAKey(2)},
		},
	}
	require.NoError(t, cs.VerifyPreconditions(env, input))
	_, err := cs.Apply(env, input)
	require.ErrorContains(t, err, "failed to register 1 of 3 nodes")

	nodes := client.snapshotNodes()
	require.Len(t, nodes, 2)
	names := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		names[node.Name] = true
	}
	assert.True(t, names["first"])
	assert.True(t, names["last"])
	actual, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual)
}
