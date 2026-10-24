package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/deployment/registration"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

type registrationTarget struct {
	role    string
	name    string
	infoURL string
	nodeID  string
}

func TestE2ESmoke_StandaloneJDRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	in, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)
	assertStandaloneJDRegistration(t, ccv.Plog.WithContext(t.Context()), in)
}

func assertStandaloneJDRegistration(t *testing.T, ctx context.Context, in *ccv.Cfg) {
	t.Helper()
	require.NotNil(t, in)
	expectedRoles := expectedStandaloneRoles(in)
	if expectedRoles == 0 {
		t.Skip("standalone JD registration is not applicable to this profile")
	}
	require.NotNil(t, in.JD)
	require.NotNil(t, in.JD.Out)
	targets := standaloneRegistrationTargets(t, in)
	require.Len(t, targets, expectedRoles)
	jdClient := newJDClient(t, in)

	conflictsChecked := false
	for _, target := range targets {
		t.Run(target.role, func(t *testing.T) {
			provider := registration.InfoServerCSAKeyProvider{URL: target.infoURL}
			csaKey, err := provider.CSAKey(ctx)
			require.NoError(t, err)

			result, err := registration.Register(ctx, jdClient, provider, jobs.DevenvNodeSpec(target.name))
			require.NoError(t, err)
			require.Equal(t, registration.StatusExisting, result.Status)
			require.Equal(t, target.nodeID, result.NodeID)
			require.NoError(t, registration.WaitForConnection(ctx, jdClient, result.NodeID, registration.WaitConfig{
				Timeout: 10 * time.Second, PollInterval: 100 * time.Millisecond,
			}))

			resp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: result.NodeID})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Node)
			require.Equal(t, target.name, resp.Node.Name)
			require.Equal(t, csaKey, resp.Node.PublicKey)
			require.True(t, resp.Node.IsConnected)
			labels := nodeLabelMap(resp.Node.Labels)
			require.Equal(t, jobs.DefaultRegistrationProduct, labels["product"])
			require.Equal(t, jobs.DefaultRegistrationEnvironment, labels["environment"])
			require.Equal(t, "plugin", labels["type"])

			rerun, err := registration.Register(ctx, jdClient, provider, jobs.DevenvNodeSpec(target.name))
			require.NoError(t, err)
			require.Equal(t, result.NodeID, rerun.NodeID)
			require.Equal(t, registration.StatusExisting, rerun.Status)
			require.False(t, rerun.LabelsReconciled)

			if !conflictsChecked {
				assertRegistrationConflicts(t, ctx, jdClient, target.name, csaKey, target.nodeID)
				conflictsChecked = true
			}
		})
	}
}

func expectedStandaloneRoles(in *ccv.Cfg) int {
	roles := 0
	for _, verifier := range in.Verifier {
		if verifier != nil && verifier.Mode == services.Standalone {
			roles++
			break
		}
	}
	for _, executor := range in.Executor {
		if executor != nil && executor.Mode == services.Standalone {
			roles++
			break
		}
	}
	return roles
}

func standaloneRegistrationTargets(t *testing.T, in *ccv.Cfg) []registrationTarget {
	t.Helper()
	var targets []registrationTarget
	for _, verifier := range in.Verifier {
		if verifier == nil || verifier.Mode != services.Standalone || verifier.Out == nil || verifier.Out.JDNodeID == "" || verifier.Out.BootstrapDBURL == "" {
			continue
		}
		targets = append(targets, registrationTarget{
			role: "verifier", name: verifier.NOPAlias, infoURL: verifier.Out.BootstrapDBURL, nodeID: verifier.Out.JDNodeID,
		})
		break
	}
	for _, executor := range in.Executor {
		if executor == nil || executor.Mode != services.Standalone || executor.Out == nil || executor.Out.JDNodeID == "" || executor.Out.BootstrapDBURL == "" {
			continue
		}
		targets = append(targets, registrationTarget{
			role: "executor", name: executor.ContainerName, infoURL: executor.Out.BootstrapDBURL, nodeID: executor.Out.JDNodeID,
		})
		break
	}
	return targets
}

func assertRegistrationConflicts(t *testing.T, ctx context.Context, jdClient registration.JDClient, name, csaKey, nodeID string) {
	t.Helper()
	beforeResp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
	require.NoError(t, err)
	require.NotNil(t, beforeResp)
	beforeList, err := jdClient.ListNodes(ctx, &nodev1.ListNodesRequest{})
	require.NoError(t, err)
	require.NotNil(t, beforeList)

	_, err = registration.Register(ctx, jdClient, registration.StaticCSAKeyProvider(csaKey), jobs.DevenvNodeSpec(name+"-conflict"))
	require.ErrorContains(t, err, "already registered as")
	_, err = registration.Register(ctx, jdClient, registration.StaticCSAKeyProvider(differentPublicKey(csaKey)), jobs.DevenvNodeSpec(name))
	require.ErrorContains(t, err, "different CSA key")

	afterResp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
	require.NoError(t, err)
	require.NotNil(t, afterResp)
	require.True(t, proto.Equal(beforeResp.Node, afterResp.Node), "conflict checks mutated the existing JD node")
	afterList, err := jdClient.ListNodes(ctx, &nodev1.ListNodesRequest{})
	require.NoError(t, err)
	require.NotNil(t, afterList)
	require.Len(t, afterList.Nodes, len(beforeList.Nodes), "conflict checks created an additional JD node")
}

func differentPublicKey(key string) string {
	if key == "" {
		return strings.Repeat("0", 64)
	}
	replacement := "0"
	if key[0] == '0' {
		replacement = "1"
	}
	return replacement + key[1:]
}

func nodeLabelMap(labels []*ptypes.Label) map[string]string {
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		if label == nil {
			continue
		}
		result[label.Key] = ""
		if label.Value != nil {
			result[label.Key] = *label.Value
		}
	}
	return result
}
