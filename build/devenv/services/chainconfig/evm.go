package chainconfig

import (
	"fmt"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvblockchain "github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// EVMChainConfigLoader converts the provided CTF blockchain outputs to a map of chain selector to blockchain.Info.
// TODO: this should be moved out of devenv into the evm chain-specific repo eventually and registered from there.
func EVMChainConfigLoader(outputs []*ctfblockchain.Output) (map[string]any, error) {
	infos := make(map[string]any)
	for _, output := range outputs {
		info := &ccvblockchain.Info{
			ChainID:         output.ChainID,
			Type:            output.Type,
			Family:          output.Family,
			UniqueChainName: output.ContainerName,
			Nodes:           make([]*ccvblockchain.Node, 0, len(output.Nodes)),
		}

		// Convert all nodes
		for _, node := range output.Nodes {
			if node != nil {
				info.Nodes = append(info.Nodes, &ccvblockchain.Node{
					ExternalHTTPUrl: node.ExternalHTTPUrl,
					InternalHTTPUrl: node.InternalHTTPUrl,
					ExternalWSUrl:   node.ExternalWSUrl,
					InternalWSUrl:   node.InternalWSUrl,
				})
			}
		}

		details, err := chainsel.GetChainDetailsByChainIDAndFamily(output.ChainID, output.Family)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for chain %s, family %s: %w", output.ChainID, output.Family, err)
		}

		strSelector := strconv.FormatUint(details.ChainSelector, 10)

		infos[strSelector] = info
	}

	return infos, nil
}
