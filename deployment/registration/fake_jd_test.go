package registration

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

type fakeJD struct {
	offchain.Client
	mu             sync.Mutex
	nodes          map[string]*nodev1.Node
	nextID         int
	registerCalls  int
	updateCalls    int
	getNodeFunc    func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error)
	listNodesFunc  func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error)
	registerFunc   func(context.Context, *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error)
	updateNodeFunc func(context.Context, *nodev1.UpdateNodeRequest) (*nodev1.UpdateNodeResponse, error)
}

func newFakeJD() *fakeJD {
	return &fakeJD{nodes: make(map[string]*nodev1.Node), nextID: 1}
}

func (f *fakeJD) GetNode(ctx context.Context, req *nodev1.GetNodeRequest, _ ...grpc.CallOption) (*nodev1.GetNodeResponse, error) {
	if f.getNodeFunc != nil {
		return f.getNodeFunc(ctx, req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, node := range f.nodes {
		if req.Id != "" && node.Id == req.Id {
			return &nodev1.GetNodeResponse{Node: cloneNode(node)}, nil
		}
		if req.PublicKey != nil && strings.EqualFold(node.PublicKey, *req.PublicKey) {
			return &nodev1.GetNodeResponse{Node: cloneNode(node)}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "node does not exist")
}

func (f *fakeJD) ListNodes(ctx context.Context, req *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	if f.listNodesFunc != nil {
		return f.listNodesFunc(ctx, req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := &nodev1.ListNodesResponse{}
	for _, node := range f.nodes {
		if matchesFilter(node, req.Filter) {
			resp.Nodes = append(resp.Nodes, cloneNode(node))
		}
	}
	resp.TotalCount = int32(len(resp.Nodes))
	return resp, nil
}

func (f *fakeJD) RegisterNode(ctx context.Context, req *nodev1.RegisterNodeRequest, _ ...grpc.CallOption) (*nodev1.RegisterNodeResponse, error) {
	if f.registerFunc != nil {
		return f.registerFunc(ctx, req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, node := range f.nodes {
		if strings.EqualFold(node.Name, req.Name) || strings.EqualFold(node.PublicKey, req.PublicKey) {
			return nil, status.Error(codes.AlreadyExists, "node already exists")
		}
	}
	f.registerCalls++
	node := &nodev1.Node{
		Id:        fmt.Sprintf("node-%d", f.nextID),
		Name:      req.Name,
		PublicKey: req.PublicKey,
		Labels:    cloneLabels(req.Labels),
	}
	f.nextID++
	f.nodes[node.Id] = cloneNode(node)
	return &nodev1.RegisterNodeResponse{Node: cloneNode(node)}, nil
}

func (f *fakeJD) UpdateNode(ctx context.Context, req *nodev1.UpdateNodeRequest, _ ...grpc.CallOption) (*nodev1.UpdateNodeResponse, error) {
	if f.updateNodeFunc != nil {
		return f.updateNodeFunc(ctx, req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	node, ok := f.nodes[req.Id]
	if !ok {
		return nil, status.Error(codes.NotFound, "node does not exist")
	}
	f.updateCalls++
	node.Name = req.Name
	node.PublicKey = req.PublicKey
	node.Labels = cloneLabels(req.Labels)
	return &nodev1.UpdateNodeResponse{Node: cloneNode(node)}, nil
}

func (f *fakeJD) addNode(node *nodev1.Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes[node.Id] = cloneNode(node)
}

func (f *fakeJD) mutationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registerCalls + f.updateCalls
}

func (f *fakeJD) snapshotNodes() map[string]*nodev1.Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string]*nodev1.Node, len(f.nodes))
	for id, node := range f.nodes {
		result[id] = cloneNode(node)
	}
	return result
}

func matchesFilter(node *nodev1.Node, filter *nodev1.ListNodesRequest_Filter) bool {
	if filter == nil {
		return true
	}
	labels := labelMap(node.Labels)
	for _, selector := range filter.Selectors {
		if selector == nil || selector.Op != ptypes.SelectorOp_EQ {
			continue
		}
		value := ""
		if selector.Value != nil {
			value = *selector.Value
		}
		if labels[selector.Key] != value {
			return false
		}
	}
	return true
}

func cloneNode(node *nodev1.Node) *nodev1.Node {
	if node == nil {
		return nil
	}
	return proto.Clone(node).(*nodev1.Node)
}

func cloneLabels(labels []*ptypes.Label) []*ptypes.Label {
	result := make([]*ptypes.Label, 0, len(labels))
	for _, label := range labels {
		if label == nil {
			result = append(result, nil)
			continue
		}
		clone := &ptypes.Label{Key: label.Key}
		if label.Value != nil {
			value := *label.Value
			clone.Value = &value
		}
		result = append(result, clone)
	}
	return result
}

func validCSAKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return hex.EncodeToString(key)
}

func testNodeSpec(name string) NodeSpec {
	return NodeSpec{
		Name:        name,
		Product:     "ccv",
		Environment: "devenv",
		Labels:      map[string]string{"target": name},
	}
}

func nodeForSpec(spec NodeSpec, key, id string) *nodev1.Node {
	labels, _ := desiredLabels(spec)
	return &nodev1.Node{Id: id, Name: spec.Name, PublicKey: key, Labels: sortedLabels(labels)}
}
