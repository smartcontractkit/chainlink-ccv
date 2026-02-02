package jobs

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

// NodeSetClientLookup provides ChainlinkClient lookup by NOP alias from NodeSets.
// This is independent of JD infrastructure.
type NodeSetClientLookup struct {
	clientsByAlias map[string]*clclient.ChainlinkClient
	orderedClients []*clclient.ChainlinkClient
}

// NewNodeSetClientLookup creates a new lookup from NodeSets and NOP aliases.
// The nopAliases must match the order and count of CL nodes across all NodeSets.
// Returns nil when there are no CL nodes (standalone mode).
func NewNodeSetClientLookup(nodeSets []*ns.Input, nopAliases []string) (*NodeSetClientLookup, error) {
	totalNodes := countCLNodes(nodeSets)

	// In standalone mode, there are no CL nodes - return nil (no client lookup available)
	if totalNodes == 0 {
		return nil, nil
	}

	// Only validate count match when there are CL nodes to map
	if len(nopAliases) != totalNodes {
		return nil, fmt.Errorf("mismatch between NOP aliases (%d) and CL nodes (%d)", len(nopAliases), totalNodes)
	}

	lookup := &NodeSetClientLookup{
		clientsByAlias: make(map[string]*clclient.ChainlinkClient, totalNodes),
		orderedClients: make([]*clclient.ChainlinkClient, 0, totalNodes),
	}

	idx := 0
	for _, nodeSet := range nodeSets {
		if nodeSet.Out == nil || len(nodeSet.Out.CLNodes) == 0 {
			continue
		}
		clients, err := clclient.New(nodeSet.Out.CLNodes)
		if err != nil {
			return nil, fmt.Errorf("failed to create CL clients: %w", err)
		}
		for _, client := range clients {
			lookup.clientsByAlias[nopAliases[idx]] = client
			lookup.orderedClients = append(lookup.orderedClients, client)
			idx++
		}
	}
	return lookup, nil
}

// GetClient returns the ChainlinkClient for the given alias.
func (l *NodeSetClientLookup) GetClient(alias string) (*clclient.ChainlinkClient, bool) {
	client, ok := l.clientsByAlias[alias]
	return client, ok
}

// AllClients returns all ChainlinkClients in order.
func (l *NodeSetClientLookup) AllClients() []*clclient.ChainlinkClient {
	return l.orderedClients
}

// Len returns the number of clients.
func (l *NodeSetClientLookup) Len() int {
	return len(l.orderedClients)
}

func countCLNodes(nodeSets []*ns.Input) int {
	count := 0
	for _, nodeSet := range nodeSets {
		if nodeSet.Out != nil {
			count += len(nodeSet.Out.CLNodes)
		}
	}
	return count
}
