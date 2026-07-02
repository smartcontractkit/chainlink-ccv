package adapters

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	cv "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// EVMCCVCommitteeVerifierOnchainAdapter implements ccvadapters.CommitteeVerifierOnchainAdapter
// for EVM chains. It is registered into the ccv adapter registry from init() so that
// ccv/deployment changesets can call it chain-family-agnostically.
type EVMCCVCommitteeVerifierOnchainAdapter struct{}

var _ ccvadapters.CommitteeVerifierOnchainAdapter = (*EVMCCVCommitteeVerifierOnchainAdapter)(nil)

func (a *EVMCCVCommitteeVerifierOnchainAdapter) ScanCommitteeStates(
	ctx context.Context,
	env deployment.Environment,
	chainSelector uint64,
) ([]*ccvadapters.CommitteeState, error) {
	refs := env.DataStore.Addresses().Filter(
		datastore.AddressRefByType(datastore.ContractType(committee_verifier.ContractType)),
		datastore.AddressRefByChainSelector(chainSelector),
	)
	if len(refs) == 0 {
		return nil, nil
	}

	evmChains := env.BlockChains.EVMChains()
	chain, ok := evmChains[chainSelector]
	if !ok {
		return nil, fmt.Errorf("EVM chain %d not found in environment", chainSelector)
	}

	states := make([]*ccvadapters.CommitteeState, 0, len(refs))
	for _, ref := range refs {
		addr := common.HexToAddress(ref.Address)
		contract, err := cv.NewCommitteeVerifier(addr, chain.Client)
		if err != nil {
			return nil, fmt.Errorf("failed to bind CommitteeVerifier %s on chain %d: %w", ref.Address, chainSelector, err)
		}

		allConfigs, err := contract.GetAllSignatureConfigs(&bind.CallOpts{Context: ctx})
		if err != nil {
			return nil, fmt.Errorf("failed to get signature configs from %s on chain %d: %w", ref.Address, chainSelector, err)
		}

		sigConfigs := make([]ccvadapters.SignatureConfig, 0, len(allConfigs))
		for _, cfg := range allConfigs {
			signers := make([]string, 0, len(cfg.Signers))
			for _, signer := range cfg.Signers {
				signers = append(signers, signer.Hex())
			}
			sigConfigs = append(sigConfigs, ccvadapters.SignatureConfig{
				SourceChainSelector: cfg.SourceChainSelector,
				Signers:             signers,
				Threshold:           cfg.Threshold,
			})
		}

		states = append(states, &ccvadapters.CommitteeState{
			Qualifier:        ref.Qualifier,
			ChainSelector:    chainSelector,
			Address:          ref.Address,
			SignatureConfigs: sigConfigs,
		})
	}

	return states, nil
}

func (a *EVMCCVCommitteeVerifierOnchainAdapter) ApplySignatureConfigs(
	ctx context.Context,
	env deployment.Environment,
	destChainSelector uint64,
	qualifier string,
	change ccvadapters.SignatureConfigChange,
) error {
	refs := env.DataStore.Addresses().Filter(
		datastore.AddressRefByType(datastore.ContractType(committee_verifier.ContractType)),
		datastore.AddressRefByChainSelector(destChainSelector),
		datastore.AddressRefByQualifier(qualifier),
	)
	if len(refs) == 0 {
		return fmt.Errorf("no CommitteeVerifier found for chain %d qualifier %q", destChainSelector, qualifier)
	}
	if len(refs) > 1 {
		return fmt.Errorf("multiple CommitteeVerifiers found for chain %d qualifier %q", destChainSelector, qualifier)
	}

	evmChains := env.BlockChains.EVMChains()
	chain, ok := evmChains[destChainSelector]
	if !ok {
		return fmt.Errorf("EVM chain %d not found in environment", destChainSelector)
	}

	addr := common.HexToAddress(refs[0].Address)
	contract, err := cv.NewCommitteeVerifier(addr, chain.Client)
	if err != nil {
		return fmt.Errorf("failed to bind CommitteeVerifier %s on chain %d: %w", refs[0].Address, destChainSelector, err)
	}

	sigConfigs := make([]cv.SignatureQuorumValidatorSignatureConfig, 0, len(change.NewConfigs))
	for _, c := range change.NewConfigs {
		signers := make([]common.Address, 0, len(c.Signers))
		for _, s := range c.Signers {
			if !common.IsHexAddress(s) {
				return fmt.Errorf("invalid signer address %q for source chain %d", s, c.SourceChainSelector)
			}
			signers = append(signers, common.HexToAddress(s))
		}
		sigConfigs = append(sigConfigs, cv.SignatureQuorumValidatorSignatureConfig{
			SourceChainSelector: c.SourceChainSelector,
			Threshold:           c.Threshold,
			Signers:             signers,
		})
	}

	tx, err := contract.ApplySignatureConfigs(chain.DeployerKey, change.RemovedSourceChainSelectors, sigConfigs)
	if err != nil {
		return fmt.Errorf("ApplySignatureConfigs tx failed on chain %d: %w", destChainSelector, err)
	}

	_, err = bind.WaitMined(ctx, chain.Client, tx)
	if err != nil {
		return fmt.Errorf("waiting for ApplySignatureConfigs tx on chain %d: %w", destChainSelector, err)
	}

	return nil
}

func (a *EVMCCVCommitteeVerifierOnchainAdapter) SetAllowedFinalityConfig(
	ctx context.Context,
	env deployment.Environment,
	chainSelector uint64,
	qualifier string,
	waitForFinality bool,
	waitForSafe bool,
	blockDepth uint16,
) error {
	chain, ok := env.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return fmt.Errorf("EVM chain %d not found in environment", chainSelector)
	}
	addr, err := committeeVerifierAddress(env, chainSelector, qualifier)
	if err != nil {
		return err
	}
	contract, err := cv.NewCommitteeVerifier(addr, chain.Client)
	if err != nil {
		return fmt.Errorf("failed to bind CommitteeVerifier %s on chain %d: %w", addr, chainSelector, err)
	}

	raw := finality.Config{
		WaitForFinality: waitForFinality,
		WaitForSafe:     waitForSafe,
		BlockDepth:      blockDepth,
	}.Raw()

	tx, err := contract.SetAllowedFinalityConfig(chain.DeployerKey, raw)
	if err != nil {
		return fmt.Errorf("SetAllowedFinalityConfig tx failed on chain %d: %w", chainSelector, err)
	}
	if _, err := bind.WaitMined(ctx, chain.Client, tx); err != nil {
		return fmt.Errorf("waiting for SetAllowedFinalityConfig tx on chain %d: %w", chainSelector, err)
	}
	return nil
}

func (a *EVMCCVCommitteeVerifierOnchainAdapter) ApplyAllowlistUpdates(
	ctx context.Context,
	env deployment.Environment,
	chainSelector uint64,
	qualifier string,
	destChainSelector uint64,
	allowlistEnabled bool,
	addedSenders []string,
	removedSenders []string,
) error {
	chain, ok := env.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return fmt.Errorf("EVM chain %d not found in environment", chainSelector)
	}
	addr, err := committeeVerifierAddress(env, chainSelector, qualifier)
	if err != nil {
		return err
	}
	contract, err := cv.NewCommitteeVerifier(addr, chain.Client)
	if err != nil {
		return fmt.Errorf("failed to bind CommitteeVerifier %s on chain %d: %w", addr, chainSelector, err)
	}

	added, err := toEVMSenderAddresses(addedSenders, "added")
	if err != nil {
		return err
	}
	removed, err := toEVMSenderAddresses(removedSenders, "removed")
	if err != nil {
		return err
	}

	args := []cv.BaseVerifierAllowlistConfigArgs{{
		DestChainSelector:         destChainSelector,
		AllowlistEnabled:          allowlistEnabled,
		AddedAllowlistedSenders:   added,
		RemovedAllowlistedSenders: removed,
	}}

	tx, err := contract.ApplyAllowlistUpdates(chain.DeployerKey, args)
	if err != nil {
		return fmt.Errorf("ApplyAllowlistUpdates tx failed on chain %d: %w", chainSelector, err)
	}
	if _, err := bind.WaitMined(ctx, chain.Client, tx); err != nil {
		return fmt.Errorf("waiting for ApplyAllowlistUpdates tx on chain %d: %w", chainSelector, err)
	}
	return nil
}

// committeeVerifierAddress resolves the single CommitteeVerifier contract address for
// the given chain selector and committee qualifier from the datastore.
func committeeVerifierAddress(env deployment.Environment, chainSelector uint64, qualifier string) (common.Address, error) {
	refs := env.DataStore.Addresses().Filter(
		datastore.AddressRefByType(datastore.ContractType(committee_verifier.ContractType)),
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByQualifier(qualifier),
	)
	if len(refs) == 0 {
		return common.Address{}, fmt.Errorf("no CommitteeVerifier found for chain %d qualifier %q", chainSelector, qualifier)
	}
	if len(refs) > 1 {
		return common.Address{}, fmt.Errorf("multiple CommitteeVerifiers found for chain %d qualifier %q", chainSelector, qualifier)
	}
	return common.HexToAddress(refs[0].Address), nil
}

// toEVMSenderAddresses converts hex sender strings to EVM addresses, rejecting malformed input.
func toEVMSenderAddresses(senders []string, label string) ([]common.Address, error) {
	out := make([]common.Address, 0, len(senders))
	for _, s := range senders {
		if !common.IsHexAddress(s) {
			return nil, fmt.Errorf("invalid %s allowlist sender address %q", label, s)
		}
		out = append(out, common.HexToAddress(s))
	}
	return out, nil
}
