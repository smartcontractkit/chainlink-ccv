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
	var funding []devenvruntime.FundingEffect
	var proposals []devenvruntime.JobProposalEffect
	for _, eff := range effects {
		switch typed := eff.(type) {
		case devenvruntime.FundingEffect:
			funding = append(funding, typed)
		case devenvruntime.JobProposalEffect:
			proposals = append(proposals, typed)
		}
	}
	if err := executeFundingEffects(ctx, funding, accumulated); err != nil {
		return err
	}
	return executeJobProposalEffects(ctx, proposals, accumulated)
}

func executeFundingEffects(ctx context.Context, effects []devenvruntime.FundingEffect, accumulated map[string]any) error {
	if len(effects) == 0 {
		return nil
	}
	blockchains, _ := accumulated["blockchains"].([]*ctfblockchain.Input)
	if len(blockchains) == 0 {
		return nil
	}

	// Group effects by chain selector; each effect carries its own address and amount.
	effectsBySelector := make(map[uint64][]devenvruntime.FundingEffect)
	for _, fe := range effects {
		effectsBySelector[fe.ChainSelector] = append(effectsBySelector[fe.ChainSelector], fe)
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
		for _, fe := range effectsBySelector[sel.ChainSelector] {
			addrBytes, err := hex.DecodeString(fe.Address)
			if err != nil {
				return fmt.Errorf("invalid funding address %q: %w", fe.Address, err)
			}
			amount := fe.NativeAmount
			if amount == nil {
				amount = big.NewInt(5)
			}
			if err := impl.FundAddresses(ctx, bc, []protocol.UnknownAddress{protocol.UnknownAddress(addrBytes)}, amount); err != nil {
				return fmt.Errorf("funding %s on chain %d: %w", fe.Address, sel.ChainSelector, err)
			}
		}
	}
	return nil
}

func executeJobProposalEffects(ctx context.Context, effects []devenvruntime.JobProposalEffect, accumulated map[string]any) error {
	if len(effects) == 0 {
		return nil
	}
	jdInfra, _ := accumulated["jd"].(*jobs.JDInfrastructure)
	if jdInfra == nil || jdInfra.OffchainClient == nil {
		return nil
	}
	jdClient := jdInfra.OffchainClient

	for _, je := range effects {
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
