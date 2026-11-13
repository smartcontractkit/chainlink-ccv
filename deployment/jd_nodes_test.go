package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type jdNodeTestClient struct {
	shared.JDClient
	listNodes func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error)
	requests  []*nodev1.ListNodesRequest
}

func (c *jdNodeTestClient) ListNodes(
	ctx context.Context,
	req *nodev1.ListNodesRequest,
	_ ...grpc.CallOption,
) (*nodev1.ListNodesResponse, error) {
	c.requests = append(c.requests, proto.Clone(req).(*nodev1.ListNodesRequest))
	return c.listNodes(ctx, req)
}

func TestJDNodesRoundTrip(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	want := map[string]JDNode{
		"node-cl": {
			Name:   "chainlink-ccv-0",
			CSAKey: "csa-cl",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "chainlink-ccv-0"},
		},
		"node-canton": {
			Name:   "canton-verifier-0",
			CSAKey: "csa-canton",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "canton-verifier-0", "component": "canton-verifier"},
		},
		"node-solana": {
			Name:   "solana-executor-0",
			CSAKey: "csa-solana",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "solana-executor-0", "chain": "solana"},
		},
	}
	require.NoError(t, SaveJDNodes(ds, want))

	got, err := GetJDNodes(ds.Seal())
	require.NoError(t, err)
	require.Equal(t, want, got)

	envMeta, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	raw, err := json.Marshal(envMeta.Metadata)
	require.NoError(t, err)
	var root map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &root))
	var offchain map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(root["offchainConfigs"], &offchain))
	require.Contains(t, offchain, "jdNodes")
	var persisted map[string]map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(offchain["jdNodes"], &persisted))
	require.Len(t, persisted, 3)
	for id, fields := range persisted {
		require.ElementsMatch(t, []string{"name", "csaKey", "labels"}, jdNodeTestKeys(fields), "node %s", id)
	}
}

func TestSaveJDNodesReplacesSnapshotAndPreservesMetadata(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ds.EnvMetadata().Set(datastore.EnvMetadata{Metadata: map[string]any{
		"futureTopLevel": map[string]any{"enabled": true},
		"offchainConfigs": map[string]any{
			"futureOffchainConfig": map[string]any{"mode": "keep"},
			"nopSigners":           map[string]any{"nop-1": map[string]any{"EVM": "0x123"}},
		},
	}}))
	require.NoError(t, SaveJDNodes(ds, map[string]JDNode{
		"node-old":    {Name: "old", CSAKey: "csa-old", Labels: map[string]string{"target": "old"}},
		"node-remove": {Name: "remove", CSAKey: "csa-remove", Labels: map[string]string{"target": "remove"}},
	}))

	replacement := map[string]JDNode{
		"node-old": {Name: "updated", CSAKey: "csa-new", Labels: map[string]string{"target": "updated"}},
	}
	require.NoError(t, SaveJDNodes(ds, replacement))
	got, err := GetJDNodes(ds.Seal())
	require.NoError(t, err)
	require.Equal(t, replacement, got)
	require.NotContains(t, got, "node-remove")

	envMeta, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	metadata, ok := envMeta.Metadata.(map[string]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"enabled": true}, metadata["futureTopLevel"])
	offchain, ok := metadata["offchainConfigs"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"mode": "keep"}, offchain["futureOffchainConfig"])
	require.Equal(t, map[string]any{"nop-1": map[string]any{"EVM": "0x123"}}, offchain["nopSigners"])
}

func TestGetJDNodesWithoutMetadata(t *testing.T) {
	t.Parallel()

	got, err := GetJDNodes(datastore.NewMemoryDataStore().Seal())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}

func TestSyncJDNodesPaginatesFiltersAndCopiesLabels(t *testing.T) {
	t.Parallel()

	nodes := []*nodev1.Node{
		jdNodeTestProto("cl-1", "chainlink-ccv-0", "csa-cl", map[string]string{
			"product": "ccv", "environment": "test", "target": "chainlink-ccv-0", "node-type": "cl",
		}),
		jdNodeTestProto("decoy", "other-product", "csa-decoy", map[string]string{
			"product": "other", "environment": "test", "target": "must-not-be-stored",
		}),
		jdNodeTestProto("canton-1", "standalone-verifier-canton-0", "csa-canton", map[string]string{
			"product": "ccv", "environment": "test", "target": "standalone-verifier-canton-0", "chain-family": "canton",
		}),
		jdNodeTestProto("solana-1", "standalone-executor-solana-0", "csa-solana", map[string]string{
			"product": "ccv", "environment": "test", "target": "standalone-executor-solana-0", "chain-family": "solana",
		}),
	}
	client := newJDNodeTestPagedClient(nodes, 2)
	ds := datastore.NewMemoryDataStore()

	count, err := SyncJDNodes(t.Context(), ds, client, "ccv", "test")
	require.NoError(t, err)
	require.Equal(t, 3, count)

	got, err := GetJDNodes(ds.Seal())
	require.NoError(t, err)
	require.Equal(t, map[string]JDNode{
		"cl-1": {
			Name: "chainlink-ccv-0", CSAKey: "csa-cl",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "chainlink-ccv-0", "node-type": "cl"},
		},
		"canton-1": {
			Name: "standalone-verifier-canton-0", CSAKey: "csa-canton",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "standalone-verifier-canton-0", "chain-family": "canton"},
		},
		"solana-1": {
			Name: "standalone-executor-solana-0", CSAKey: "csa-solana",
			Labels: map[string]string{"product": "ccv", "environment": "test", "target": "standalone-executor-solana-0", "chain-family": "solana"},
		},
	}, got)
	require.NotContains(t, got, "decoy")

	require.Len(t, client.requests, 2)
	for i, req := range client.requests {
		require.Equal(t, int32(i+1), req.GetPage())
		require.Equal(t, jdNodesPageSize, req.GetPageSize())
		require.Empty(t, req.GetFilter().GetIds())
		require.Empty(t, req.GetFilter().GetPublicKeys())
		selectors := req.GetFilter().GetSelectors()
		require.Len(t, selectors, 2)
		for _, selector := range selectors {
			require.Equal(t, ptypes.SelectorOp_EQ, selector.GetOp())
			require.NotNil(t, selector.Value)
		}
		require.Equal(t, "product", selectors[0].GetKey())
		require.Equal(t, "ccv", selectors[0].GetValue())
		require.Equal(t, "environment", selectors[1].GetKey())
		require.Equal(t, "test", selectors[1].GetValue())
	}
}

func TestSyncJDNodesReplacesRemovedNodes(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	first := newJDNodeTestPagedClient([]*nodev1.Node{
		jdNodeTestProto("keep", "old-name", "old-key", map[string]string{"product": "ccv", "environment": "test", "target": "old"}),
		jdNodeTestProto("remove", "removed", "removed-key", map[string]string{"product": "ccv", "environment": "test", "target": "removed"}),
	}, 1)
	count, err := SyncJDNodes(t.Context(), ds, first, "ccv", "test")
	require.NoError(t, err)
	require.Equal(t, 2, count)

	second := newJDNodeTestPagedClient([]*nodev1.Node{
		jdNodeTestProto("keep", "new-name", "new-key", map[string]string{"product": "ccv", "environment": "test", "target": "new"}),
	}, 1)
	count, err = SyncJDNodes(t.Context(), ds, second, "ccv", "test")
	require.NoError(t, err)
	require.Equal(t, 1, count)

	got, err := GetJDNodes(ds.Seal())
	require.NoError(t, err)
	require.Equal(t, map[string]JDNode{
		"keep": {Name: "new-name", CSAKey: "new-key", Labels: map[string]string{"product": "ccv", "environment": "test", "target": "new"}},
	}, got)
}

func TestSyncJDNodesErrorsPreservePriorSnapshot(t *testing.T) {
	t.Parallel()

	valid := func() *nodev1.Node {
		return jdNodeTestProto("new-node", "new-name", "new-key", map[string]string{"product": "ccv", "environment": "test"})
	}
	tests := []struct {
		name      string
		listNodes func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error)
		wantError string
	}{
		{
			name: "nil node",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{nil}, TotalCount: 1}, nil
			},
			wantError: "nil JD node",
		},
		{
			name: "empty ID",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				node := valid()
				node.Id = ""
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{node}, TotalCount: 1}, nil
			},
			wantError: "empty ID",
		},
		{
			name: "empty name",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				node := valid()
				node.Name = ""
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{node}, TotalCount: 1}, nil
			},
			wantError: "empty name",
		},
		{
			name: "empty public key",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				node := valid()
				node.PublicKey = ""
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{node}, TotalCount: 1}, nil
			},
			wantError: "empty CSA public key",
		},
		{
			name: "duplicate ID in one page",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{valid(), valid()}, TotalCount: 2}, nil
			},
			wantError: "duplicate JD node ID",
		},
		{
			name: "duplicate ID across pages",
			listNodes: func(_ context.Context, req *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{valid()}, TotalCount: 2}, nil
			},
			wantError: "duplicate JD node ID",
		},
		{
			name: "empty inventory",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return &nodev1.ListNodesResponse{}, nil
			},
			wantError: "refusing to save an empty inventory",
		},
		{
			name: "nil response",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return nil, nil
			},
			wantError: "nil JD list nodes response",
		},
		{
			name: "list failure",
			listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				return nil, errors.New("JD unavailable")
			},
			wantError: "JD unavailable",
		},
		{
			name: "incomplete pagination",
			listNodes: func(_ context.Context, req *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
				if req.GetPage() == 1 {
					return &nodev1.ListNodesResponse{Nodes: []*nodev1.Node{valid()}, TotalCount: 2}, nil
				}
				return &nodev1.ListNodesResponse{TotalCount: 2}, nil
			},
			wantError: "incomplete JD node inventory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ds := datastore.NewMemoryDataStore()
			prior := map[string]JDNode{
				"prior": {Name: "prior", CSAKey: "prior-key", Labels: map[string]string{"target": "prior"}},
			}
			require.NoError(t, SaveJDNodes(ds, prior))
			client := &jdNodeTestClient{listNodes: tt.listNodes}

			count, err := SyncJDNodes(t.Context(), ds, client, "ccv", "test")
			require.ErrorContains(t, err, tt.wantError)
			require.Zero(t, count)
			got, getErr := GetJDNodes(ds.Seal())
			require.NoError(t, getErr)
			require.Equal(t, prior, got)
		})
	}
}

func TestSyncJDNodesValidatesInputs(t *testing.T) {
	t.Parallel()

	called := false
	client := &jdNodeTestClient{listNodes: func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
		called = true
		return nil, errors.New("unexpected call")
	}}
	for _, tt := range []struct {
		name                 string
		client               shared.JDClient
		product, environment string
		wantError            string
	}{
		{name: "nil client", product: "ccv", environment: "test", wantError: "JD client is required"},
		{name: "empty product", client: client, environment: "test", wantError: "product is required"},
		{name: "empty environment", client: client, product: "ccv", wantError: "environment is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			count, err := SyncJDNodes(t.Context(), datastore.NewMemoryDataStore(), tt.client, tt.product, tt.environment)
			require.ErrorContains(t, err, tt.wantError)
			require.Zero(t, count)
		})
	}
	require.False(t, called)
}

func newJDNodeTestPagedClient(nodes []*nodev1.Node, pageSize int32) *jdNodeTestClient {
	return &jdNodeTestClient{listNodes: func(_ context.Context, req *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
		filtered := make([]*nodev1.Node, 0, len(nodes))
		for _, node := range nodes {
			if jdNodeTestMatchesSelectors(node, req.GetFilter().GetSelectors()) {
				filtered = append(filtered, node)
			}
		}
		start := int((req.GetPage() - 1) * pageSize)
		if start >= len(filtered) {
			return &nodev1.ListNodesResponse{TotalCount: int32(len(filtered))}, nil
		}
		end := min(start+int(pageSize), len(filtered))
		return &nodev1.ListNodesResponse{Nodes: filtered[start:end], TotalCount: int32(len(filtered))}, nil
	}}
}

func jdNodeTestMatchesSelectors(node *nodev1.Node, selectors []*ptypes.Selector) bool {
	labels := make(map[string]string, len(node.GetLabels()))
	for _, label := range node.GetLabels() {
		if label != nil {
			labels[label.GetKey()] = label.GetValue()
		}
	}
	for _, selector := range selectors {
		if selector.GetOp() != ptypes.SelectorOp_EQ || labels[selector.GetKey()] != selector.GetValue() {
			return false
		}
	}
	return true
}

func jdNodeTestProto(id, name, csaKey string, labels map[string]string) *nodev1.Node {
	keys := jdNodeTestKeys(labels)
	node := &nodev1.Node{Id: id, Name: name, PublicKey: csaKey}
	for i := len(keys) - 1; i >= 0; i-- {
		value := labels[keys[i]]
		node.Labels = append(node.Labels, &ptypes.Label{Key: keys[i], Value: &value})
	}
	return node
}

func jdNodeTestKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
