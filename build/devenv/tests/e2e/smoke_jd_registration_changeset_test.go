package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	"github.com/smartcontractkit/chainlink-ccv/deployment/registration"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

func assertJDRegistrationChangesets(t *testing.T, ctx context.Context, jdClient offchain.Client) {
	t.Helper()
	t.Run("shared_changesets", func(t *testing.T) {
		runID := strconv.FormatInt(time.Now().UnixNano(), 36)
		domainKey := "ccv-registration-e2e"
		envKey := "devenv-" + runID
		d := domain.NewDomain(t.TempDir(), domainKey)
		require.NoError(t, os.MkdirAll(d.EnvDir(envKey).DirPath(), 0o700))

		_, env, err := ccldf.NewCLDFOperationsEnvironmentWithOffchain(ccldf.CLDFEnvironmentConfig{
			DataStore:      datastore.NewMemoryDataStore().Seal(),
			OffchainClient: jdClient,
		})
		require.NoError(t, err)
		env.Name = envKey
		changeset := registration.CsRegisterNodesWithJD{Domain: &d}
		input := registration.CsRegisterNodesWithJDInput{
			Domain: domainKey,
			Nodes: []registration.NodeToRegisterJD{
				{Name: "synthetic-verifier-" + runID, CSAKey: syntheticCSAKey(t), Labels: map[string]string{"role": "verifier"}},
				{Name: "synthetic-bootstrap-" + runID, CSAKey: syntheticCSAKey(t), IsBootstrap: true, Labels: map[string]string{"role": "bootstrap"}},
			},
		}
		require.NoError(t, changeset.VerifyPreconditions(*env, input))

		apply := func(input registration.CsRegisterNodesWithJDInput) []operations.Report[any, any] {
			reporter := operations.NewMemoryReporter()
			env.OperationsBundle = operations.NewBundle(func() context.Context { return ctx }, env.Logger, reporter)
			_, err := changeset.Apply(*env, input)
			require.NoError(t, err)
			reports, err := reporter.GetReports()
			require.NoError(t, err)
			require.Len(t, reports, 3)
			return reports
		}
		registerOutput := func(report operations.Report[any, any], wantRegistered bool) registration.RegisterNodeOutput {
			require.Equal(t, "register-node-with-jd", report.Def.ID)
			output, ok := report.Output.(registration.RegisterNodeOutput)
			require.True(t, ok)
			require.Equal(t, wantRegistered, output.WasRegistered)
			require.NotEmpty(t, output.NodeID)
			return output
		}
		saveOutput := func(report operations.Report[any, any]) registration.SaveNodesJSONOutput {
			require.Equal(t, "save-nodes-json", report.Def.ID)
			output, ok := report.Output.(registration.SaveNodesJSONOutput)
			require.True(t, ok)
			require.Equal(t, 2, output.NodeCount)
			return output
		}

		firstReports := apply(input)
		verifier := registerOutput(firstReports[0], true)
		bootstrap := registerOutput(firstReports[1], true)
		require.NotEqual(t, verifier.NodeID, bootstrap.NodeID)
		save := saveOutput(firstReports[2])
		nodesPath := d.EnvDir(envKey).NodesFilePath()
		require.Equal(t, nodesPath, save.Path)
		state := readRegistrationNodesState(t, nodesPath)
		require.Len(t, state.Nodes, 2)
		require.Equal(t, input.Nodes[0].Name, state.Nodes[verifier.NodeID]["name"])
		require.Equal(t, input.Nodes[1].Name, state.Nodes[bootstrap.NodeID]["name"])
		firstState, err := os.ReadFile(nodesPath)
		require.NoError(t, err)

		for _, item := range []struct {
			output registration.RegisterNodeOutput
			input  registration.NodeToRegisterJD
		}{
			{output: verifier, input: input.Nodes[0]},
			{output: bootstrap, input: input.Nodes[1]},
		} {
			resp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: item.output.NodeID})
			require.NoError(t, err)
			require.Equal(t, item.input.CSAKey, resp.Node.PublicKey)
			labels := nodeLabelMap(resp.Node.Labels)
			require.Equal(t, domainKey, labels["product"])
			require.Equal(t, envKey, labels["environment"])
			require.Equal(t, item.input.Labels["role"], labels["role"])
			expectedType := "plugin"
			if item.input.IsBootstrap {
				expectedType = "bootstrap"
			}
			require.Equal(t, expectedType, labels["type"])
		}

		rerunReports := apply(input)
		rerunVerifier := registerOutput(rerunReports[0], false)
		rerunBootstrap := registerOutput(rerunReports[1], false)
		require.Equal(t, verifier.NodeID, rerunVerifier.NodeID)
		require.Equal(t, bootstrap.NodeID, rerunBootstrap.NodeID)
		saveOutput(rerunReports[2])
		rerunState, err := os.ReadFile(nodesPath)
		require.NoError(t, err)
		require.Equal(t, firstState, rerunState)

		resp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: verifier.NodeID})
		require.NoError(t, err)
		unrelatedValue := "keep"
		_, err = jdClient.UpdateNode(ctx, &nodev1.UpdateNodeRequest{
			Id:        resp.Node.Id,
			Name:      resp.Node.Name,
			PublicKey: resp.Node.PublicKey,
			Labels:    append(resp.Node.Labels, &ptypes.Label{Key: "unrelated", Value: &unrelatedValue}),
		})
		require.NoError(t, err)
		input.Nodes[0].Labels["role"] = "reconciled"
		reconciledReports := apply(input)
		reconciled := registerOutput(reconciledReports[0], false)
		require.Equal(t, verifier.NodeID, reconciled.NodeID)
		resp, err = jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: verifier.NodeID})
		require.NoError(t, err)
		labels := nodeLabelMap(resp.Node.Labels)
		require.Equal(t, "reconciled", labels["role"])
		require.Equal(t, "keep", labels["unrelated"])

		result, err := registration.Register(ctx, jdClient, registration.StaticCSAKeyProvider(input.Nodes[0].CSAKey), registration.NodeSpec{
			Name: input.Nodes[0].Name, Product: domainKey, Environment: envKey, Labels: input.Nodes[0].Labels,
		})
		require.NoError(t, err)
		require.Equal(t, registration.StatusExisting, result.Status)
		require.False(t, result.LabelsReconciled)

		conflictInput := registration.CsRegisterNodesWithJDInput{
			Domain: domainKey,
			Nodes: []registration.NodeToRegisterJD{
				{Name: "conflicting-name-" + runID, CSAKey: input.Nodes[0].CSAKey},
				{Name: "after-conflict-" + runID, CSAKey: syntheticCSAKey(t)},
			},
		}
		require.NoError(t, changeset.VerifyPreconditions(*env, conflictInput))
		reporter := operations.NewMemoryReporter()
		env.OperationsBundle = operations.NewBundle(func() context.Context { return ctx }, env.Logger, reporter)
		_, err = changeset.Apply(*env, conflictInput)
		require.ErrorContains(t, err, "failed to register 1 of 2 nodes")
		conflictReports, err := reporter.GetReports()
		require.NoError(t, err)
		require.Len(t, conflictReports, 2)
		for _, report := range conflictReports {
			require.Equal(t, "register-node-with-jd", report.Def.ID)
		}
		afterConflict, err := os.ReadFile(nodesPath)
		require.NoError(t, err)
		require.Equal(t, firstState, afterConflict)
		newNode, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{PublicKey: &conflictInput.Nodes[1].CSAKey})
		require.NoError(t, err)
		require.Equal(t, conflictInput.Nodes[1].Name, newNode.Node.Name)
		_, present := readRegistrationNodesState(t, nodesPath).Nodes[newNode.Node.Id]
		assert.False(t, present, "a partial batch failure must not refresh nodes.json")
	})
}

type registrationNodesState struct {
	Nodes map[string]map[string]string `json:"nodes"`
}

func readRegistrationNodesState(t *testing.T, path string) registrationNodesState {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var state registrationNodesState
	require.NoError(t, json.Unmarshal(data, &state))
	return state
}

func syntheticCSAKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return hex.EncodeToString(key)
}
