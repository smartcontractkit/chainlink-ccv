package registration

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

type SaveNodesJSONDeps struct {
	JDClient offchain.Client
	Domain   domain.Domain
	EnvKey   string
}

type SaveNodesJSONOutput struct {
	Path      string                          `json:"path"`
	NodeCount int                             `json:"node_count"`
	Nodes     map[string]ccvdeployment.JDNode `json:"-" yaml:"-"`
}

// SaveNodesJSON snapshots the full JD product/environment into nodes.json.
var SaveNodesJSON = operations.NewOperation(
	"save-nodes-json",
	semver.MustParse("1.0.0"),
	"Lists JD nodes by product and environment labels and writes them to nodes.json",
	func(b operations.Bundle, deps SaveNodesJSONDeps, _ operations.EmptyInput) (SaveNodesJSONOutput, error) {
		domainKey := deps.Domain.Key()
		envKey := deps.EnvKey

		nodes, err := ccvdeployment.FetchJDNodes(b.GetContext(), deps.JDClient, domainKey, envKey)
		if err != nil {
			return SaveNodesJSONOutput{}, err
		}
		if len(nodes) == 0 {
			return SaveNodesJSONOutput{}, fmt.Errorf(
				"no nodes registered in JD for product=%s environment=%s, refusing to overwrite nodes.json with an empty result",
				domainKey, envKey)
		}

		nodesData := struct {
			Nodes map[string]map[string]string `json:"nodes"`
		}{
			Nodes: make(map[string]map[string]string, len(nodes)),
		}
		for id, node := range nodes {
			nodesData.Nodes[id] = map[string]string{"name": node.Name}
		}

		jsonData, err := json.MarshalIndent(nodesData, "", "  ")
		if err != nil {
			return SaveNodesJSONOutput{}, fmt.Errorf("failed to marshal nodes data: %w", err)
		}

		nodesFilePath := deps.Domain.EnvDir(envKey).NodesFilePath()
		if err := os.WriteFile(nodesFilePath, jsonData, 0o600); err != nil {
			return SaveNodesJSONOutput{}, fmt.Errorf("failed to write nodes.json file: %w", err)
		}

		return SaveNodesJSONOutput{Path: nodesFilePath, NodeCount: len(nodes), Nodes: nodes}, nil
	},
)
