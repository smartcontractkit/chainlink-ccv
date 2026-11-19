package deployment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const jdNodesPageSize int32 = 100

// JDProduct is the JD product label on CCV nodes; registration sets it from the CLD domain key.
const JDProduct = "ccv"

// JDNode is the durable, non-sensitive portion of a JD node inventory entry.
type JDNode struct {
	Name   string            `json:"name"`
	CSAKey string            `json:"csaKey"`
	Labels map[string]string `json:"labels"`
}

// SaveJDNodes replaces the complete JD node snapshot without changing other metadata.
func SaveJDNodes(ds datastore.MutableDataStore, nodes map[string]JDNode) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}
	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if nodes == nil {
		nodes = make(map[string]JDNode)
	}
	ccvMeta.OffchainConfigs.JDNodes = nodes
	return persistCCVEnvMetadata(ds, ccvMeta)
}

// GetJDNodes returns the persisted snapshot, or an empty map when none exists.
func GetJDNodes(ds datastore.DataStore) (map[string]JDNode, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		if errors.Is(err, datastore.ErrEnvMetadataNotSet) {
			return make(map[string]JDNode), nil
		}
		return nil, err
	}
	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.JDNodes == nil {
		return make(map[string]JDNode), nil
	}
	return ccvMeta.OffchainConfigs.JDNodes, nil
}

// FetchJDNodes fetches and validates the complete product/environment inventory without writing it.
func FetchJDNodes(ctx context.Context, client shared.JDClient, product, environment string) (map[string]JDNode, error) {
	if client == nil {
		return nil, fmt.Errorf("JD client is required")
	}
	if strings.TrimSpace(product) == "" {
		return nil, fmt.Errorf("JD node product is required")
	}
	if strings.TrimSpace(environment) == "" {
		return nil, fmt.Errorf("JD node environment is required")
	}

	nodes := make(map[string]JDNode)
	responseCount := 0
	for page := int32(1); ; page++ {
		resp, err := client.ListNodes(ctx, &nodev1.ListNodesRequest{
			Filter: &nodev1.ListNodesRequest_Filter{Selectors: []*ptypes.Selector{
				{Key: "product", Op: ptypes.SelectorOp_EQ, Value: &product},
				{Key: "environment", Op: ptypes.SelectorOp_EQ, Value: &environment},
			}},
			PageSize: jdNodesPageSize,
			Page:     page,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list JD nodes for product=%s environment=%s page=%d: %w", product, environment, page, err)
		}
		if resp == nil {
			return nil, fmt.Errorf("nil JD list nodes response for product=%s environment=%s page=%d", product, environment, page)
		}
		if resp.GetTotalCount() < 0 {
			return nil, fmt.Errorf("invalid negative JD node total count %d", resp.GetTotalCount())
		}

		pageNodes := resp.GetNodes()
		for _, node := range pageNodes {
			if node == nil {
				return nil, fmt.Errorf("nil JD node for product=%s environment=%s", product, environment)
			}
			if strings.TrimSpace(node.GetId()) == "" {
				return nil, fmt.Errorf("JD node has an empty ID")
			}
			if strings.TrimSpace(node.GetName()) == "" {
				return nil, fmt.Errorf("JD node %q has an empty name", node.GetId())
			}
			if strings.TrimSpace(node.GetPublicKey()) == "" {
				return nil, fmt.Errorf("JD node %q has an empty CSA public key", node.GetId())
			}
			if _, exists := nodes[node.GetId()]; exists {
				return nil, fmt.Errorf("duplicate JD node ID %q", node.GetId())
			}

			labels := make(map[string]string, len(node.GetLabels()))
			for _, label := range node.GetLabels() {
				if label != nil {
					labels[label.GetKey()] = label.GetValue()
				}
			}
			nodes[node.GetId()] = JDNode{Name: node.GetName(), CSAKey: node.GetPublicKey(), Labels: labels}
			responseCount++
		}

		total := int(resp.GetTotalCount())
		if total > 0 && responseCount > total {
			return nil, fmt.Errorf("JD returned %d nodes, exceeding total count %d", responseCount, total)
		}
		if len(pageNodes) == 0 {
			if total > responseCount {
				return nil, fmt.Errorf("incomplete JD node inventory: received %d of %d nodes", responseCount, total)
			}
			break
		}
		if total > 0 {
			if responseCount == total {
				break
			}
		} else if len(pageNodes) < int(jdNodesPageSize) {
			break
		}
	}

	return nodes, nil
}

// SyncJDNodes fetches the complete product/environment inventory and saves it atomically.
// Empty or malformed responses are rejected so they cannot erase a valid prior snapshot.
func SyncJDNodes(
	ctx context.Context,
	ds datastore.MutableDataStore,
	client shared.JDClient,
	product, environment string,
) (int, error) {
	nodes, err := FetchJDNodes(ctx, client, product, environment)
	if err != nil {
		return 0, err
	}
	if len(nodes) == 0 {
		return 0, fmt.Errorf("no JD nodes found for product=%s environment=%s; refusing to save an empty inventory", product, environment)
	}
	if err := SaveJDNodes(ds, nodes); err != nil {
		return 0, fmt.Errorf("failed to save JD node inventory: %w", err)
	}
	return len(nodes), nil
}
