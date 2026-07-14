package chainconfig

import (
	"fmt"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	accessorevm "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ConvertBlockchainOutputsToInfo converts EVM CTF blockchain outputs to accessor configuration
// keyed by chain selector. Non-EVM outputs are ignored.
func ConvertBlockchainOutputsToInfo(outputs []*ctfblockchain.Output) (chainaccess.Infos[accessorevm.Info], error) {
	infos := make(chainaccess.Infos[accessorevm.Info])
	for _, output := range outputs {
		if output.Family != chainsel.FamilyEVM {
			continue
		}

		info := accessorevm.Info{
			ChainID:         output.ChainID,
			Type:            output.Type,
			Family:          output.Family,
			UniqueChainName: output.ContainerName,
			Nodes:           make([]accessorevm.Node, 0, len(output.Nodes)),
		}

		for _, node := range output.Nodes {
			if node != nil {
				info.Nodes = append(info.Nodes, accessorevm.Node{
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

		infos[strconv.FormatUint(details.ChainSelector, 10)] = info
	}

	return infos, nil
}
