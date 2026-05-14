package pricer

import (
	"context"
	"fmt"
	"math/big"

	"github.com/pelletier/go-toml/v2"

	chainsel "github.com/smartcontractkit/chain-selectors"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "pricer"

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

	if _, err := services.NewPricer(input); err != nil {
		return nil, nil, fmt.Errorf("starting pricer: %w", err)
	}

	blockchains, _ := priorOutputs["blockchains"].([]*ctfblockchain.Input)

	services.ApplyPricerDefaults(input)
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

// decode round-trips the raw TOML map[string]any into *services.PricerInput.
func decode(raw any) (*services.PricerInput, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"pricer"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding pricer config: %w", err)
	}
	var wrapper struct {
		V *services.PricerInput `toml:"pricer"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding pricer config: %w", err)
	}
	return wrapper.V, nil
}
