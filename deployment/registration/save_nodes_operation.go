package registration

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Masterminds/semver/v3"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"

	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

type SaveNodesJSONDeps struct {
	JDClient offchain.Client
	Domain   domain.Domain
	EnvKey   string
}

type SaveNodesJSONOutput struct {
	Path      string `json:"path"`
	NodeCount int    `json:"node_count"`
}

// SaveNodesJSON snapshots the full JD product/environment into nodes.json.
var SaveNodesJSON = operations.NewOperation(
	"save-nodes-json",
	semver.MustParse("1.0.0"),
	"Lists JD nodes by product and environment labels and writes them to nodes.json",
	func(b operations.Bundle, deps SaveNodesJSONDeps, _ operations.EmptyInput) (SaveNodesJSONOutput, error) {
		domainKey := deps.Domain.Key()
		envKey := deps.EnvKey

		nodes, err := deps.JDClient.ListNodes(b.GetContext(), &nodev1.ListNodesRequest{
			Filter: &nodev1.ListNodesRequest_Filter{
				Selectors: []*ptypes.Selector{
					{Key: "product", Op: ptypes.SelectorOp_EQ, Value: &domainKey},
					{Key: "environment", Op: ptypes.SelectorOp_EQ, Value: &envKey},
				},
			},
		})
		if err != nil {
			return SaveNodesJSONOutput{}, fmt.Errorf("failed to list nodes from JD: %w", err)
		}

		jdNodes := nodes.GetNodes()
		if len(jdNodes) == 0 {
			return SaveNodesJSONOutput{}, fmt.Errorf(
				"no nodes registered in JD for product=%s environment=%s, refusing to overwrite nodes.json with an empty result",
				domainKey, envKey)
		}
		for _, node := range jdNodes {
			if node == nil || node.Id == "" {
				return SaveNodesJSONOutput{}, fmt.Errorf("invalid JD response while listing nodes for product=%s environment=%s", domainKey, envKey)
			}
		}

		sort.Slice(jdNodes, func(i, j int) bool {
			return jdNodes[i].Name < jdNodes[j].Name
		})

		nodesData := struct {
			Nodes map[string]map[string]string `json:"nodes"`
		}{
			Nodes: make(map[string]map[string]string, len(jdNodes)),
		}
		for _, node := range jdNodes {
			nodesData.Nodes[node.Id] = map[string]string{"name": node.Name}
		}

		jsonData, err := json.MarshalIndent(nodesData, "", "  ")
		if err != nil {
			return SaveNodesJSONOutput{}, fmt.Errorf("failed to marshal nodes data: %w", err)
		}

		nodesFilePath := deps.Domain.EnvDir(envKey).NodesFilePath()
		if err := os.WriteFile(nodesFilePath, jsonData, 0o600); err != nil {
			return SaveNodesJSONOutput{}, fmt.Errorf("failed to write nodes.json file: %w", err)
		}

		return SaveNodesJSONOutput{Path: nodesFilePath, NodeCount: len(nodesData.Nodes)}, nil
	},
)
