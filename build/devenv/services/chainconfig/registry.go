package chainconfig

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

var chainConfigLoaderRegistry = make(map[string]ChainConfigLoader)

type ChainConfigLoader func(outputs []*ctfblockchain.Output) (map[string]any, error)

func RegisterChainConfigLoader(family string, loader ChainConfigLoader) {
	chainConfigLoaderRegistry[family] = loader
}

func GetChainConfigLoader(family string) (ChainConfigLoader, error) {
	loader, ok := chainConfigLoaderRegistry[family]
	if !ok {
		return nil, fmt.Errorf("chain config loader for family %s not found", family)
	}
	return loader, nil
}

func init() {
	RegisterChainConfigLoader(chainsel.FamilyEVM, EVMChainConfigLoader)
}
