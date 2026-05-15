package e2e

import (
	chain_selectors "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
)

// FirstTwoEVMSelectors returns chain selectors for the first two EVM chains in cfg.Blockchains order.
func FirstTwoEVMSelectors(cfg *ccv.Cfg) ([]uint64, error) {
	var selectors []uint64
	for _, bc := range cfg.Blockchains {
		if bc.Out.Family != chain_selectors.FamilyEVM {
			continue
		}
		d, err := chain_selectors.GetChainDetailsByChainIDAndFamily(bc.ChainID, bc.Out.Family)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, d.ChainSelector)
		if len(selectors) >= 2 {
			break
		}
	}
	return selectors, nil
}
