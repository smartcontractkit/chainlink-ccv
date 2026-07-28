package chainconfig

import (
	"fmt"
	"strconv"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"
	accessorevm "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ConvertBlockchainOutputsToInfo converts EVM CTF blockchain outputs to accessor configuration
// keyed by chain selector. Non-EVM outputs are ignored.
//
// CTF publishes each RPC twice, once for the host and once for the Docker network. Standalone CCV
// services run in that network, so this is where the container-reachable address is chosen; the
// accessor config it produces carries a single URL per endpoint.
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
					HTTPUrl: containerReachableURL(node.InternalHTTPUrl, node.ExternalHTTPUrl),
					WSUrl:   containerReachableURL(node.InternalWSUrl, node.ExternalWSUrl),
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

// containerReachableURL prefers the Docker-network address. Blockchain outputs that only publish a
// host address, such as an external testnet RPC recorded in an env TOML, fall back to it.
func containerReachableURL(internal, external string) string {
	if url := strings.TrimSpace(internal); url != "" {
		return url
	}
	return strings.TrimSpace(external)
}
