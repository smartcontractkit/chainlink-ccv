package pricer

import (
	"context"
	"fmt"
	"math/big"

	chainsel "github.com/smartcontractkit/chain-selectors"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "pricer"

// Version is the pricer component config schema version. Exactly this version is
// supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("pricer component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decode(componentConfig)
	return err
}

// RunPhase3 starts the pricer container and emits FundingEffects for the
// pricer's keystore address on every declared blockchain.
func (c *component) RunPhase3(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	input, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	if input == nil {
		return map[string]any{configKey: input}, nil, nil
	}

	services.ApplyPricerDefaults(input)

	if _, err := services.NewPricer(input); err != nil {
		return nil, nil, fmt.Errorf("starting pricer: %w", err)
	}

	blockchains, _ := priorOutputs["blockchains"].([]*ctfblockchain.Input)

	addr, err := protocol.NewUnknownAddressFromHex(input.Keystore.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("pricer invalid keystore address: %w", err)
	}

	var effects []devenvruntime.Effect
	for _, bc := range blockchains {
		if bc == nil {
			continue
		}
		family, ferr := ctfblockchain.TypeToFamily(bc.Type)
		if ferr != nil {
			continue
		}
		sel, serr := chainsel.GetChainDetailsByChainIDAndFamily(bc.ChainID, string(family))
		if serr != nil {
			continue
		}
		effects = append(effects, devenvruntime.FundingEffect{
			ChainSelector: sel.ChainSelector,
			Address:       addr,
			NativeAmount:  big.NewInt(5),
		})
	}

	return map[string]any{configKey: input}, effects, nil
}

func decode(raw any) (*services.PricerInput, error) {
	input, err := devenvruntime.DecodeConfig[*services.PricerInput](raw, "pricer")
	if err != nil {
		return nil, err
	}
	if input != nil {
		if err := devenvruntime.CheckConfigVersion(input.Version, Version); err != nil {
			return nil, err
		}
	}
	return input, nil
}
