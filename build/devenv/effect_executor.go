package ccv

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type devenvEffectExecutor struct{}

func newDevenvEffectExecutor() *devenvEffectExecutor {
	return &devenvEffectExecutor{}
}

func (e *devenvEffectExecutor) Execute(ctx context.Context, effects []devenvruntime.Effect, accumulated map[string]any) error {
	if len(effects) == 0 {
		return nil
	}
	if err := executeFundingEffects(ctx, effects, accumulated); err != nil {
		return err
	}
	return executeJobProposalEffects(ctx, effects, accumulated)
}

func executeFundingEffects(ctx context.Context, effects []devenvruntime.Effect, accumulated map[string]any) error {
	blockchains, _ := accumulated["blockchains"].([]*ctfblockchain.Input)
	if len(blockchains) == 0 {
		return nil
	}

	// Group addresses by chain selector.
	addrsBySelector := make(map[uint64][]protocol.UnknownAddress)
	amountBySelector := make(map[uint64]*big.Int)
	for _, eff := range effects {
		fe, ok := eff.(devenvruntime.FundingEffect)
		if !ok {
			continue
		}
		addrBytes, err := hex.DecodeString(fe.Address)
		if err != nil {
			return fmt.Errorf("invalid funding address %q: %w", fe.Address, err)
		}
		addrsBySelector[fe.ChainSelector] = append(addrsBySelector[fe.ChainSelector], protocol.UnknownAddress(addrBytes))
		if amountBySelector[fe.ChainSelector] == nil {
			amountBySelector[fe.ChainSelector] = fe.NativeAmount
		}
	}
	if len(addrsBySelector) == 0 {
		return nil
	}

	for _, bc := range blockchains {
		impl, err := NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return fmt.Errorf("creating impl for blockchain %q: %w", bc.ContainerName, err)
		}
		family := impl.ChainFamily()
		fac, err := chainimpl.GetImplFactory(family)
		if err != nil || !fac.SupportsFunding() {
			continue
		}
		sel, err := chainsel.GetChainDetailsByChainIDAndFamily(bc.ChainID, family)
		if err != nil {
			return fmt.Errorf("looking up chain selector for %q: %w", bc.ChainID, err)
		}
		addrs := addrsBySelector[sel.ChainSelector]
		if len(addrs) == 0 {
			continue
		}
		amount := amountBySelector[sel.ChainSelector]
		if amount == nil {
			amount = big.NewInt(5)
		}
		if err := impl.FundAddresses(ctx, bc, addrs, amount); err != nil {
			return fmt.Errorf("funding addresses on chain %d: %w", sel.ChainSelector, err)
		}
	}
	return nil
}

func executeJobProposalEffects(ctx context.Context, effects []devenvruntime.Effect, accumulated map[string]any) error {
	jdInfra, _ := accumulated["jd"].(*jobs.JDInfrastructure)
	if jdInfra == nil || jdInfra.OffchainClient == nil {
		return nil
	}
	jdClient := jdInfra.OffchainClient

	for _, eff := range effects {
		je, ok := eff.(devenvruntime.JobProposalEffect)
		if !ok {
			continue
		}
		_, err := jdClient.ProposeJob(ctx, &jobv1.ProposeJobRequest{
			NodeId: je.NodeID,
			Spec:   je.JobSpec,
		})
		if err != nil {
			return fmt.Errorf("proposing job to node %s (nop %s): %w", je.NodeID, je.NOPAlias, err)
		}
	}
	return nil
}
