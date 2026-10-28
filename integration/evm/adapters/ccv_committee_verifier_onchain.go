package adapters

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	cv "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

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
	_ context.Context,
	env deployment.Environment,
	destChainSelector uint64,
	qualifier string,
	change ccvadapters.SignatureConfigChange,
) ([]mcmstypes.BatchOperation, error) {
	sigConfigs := make([]committee_verifier.SignatureConfig, 0, len(change.NewConfigs))
	for _, c := range change.NewConfigs {
		signers := make([]common.Address, 0, len(c.Signers))
		for _, s := range c.Signers {
			if !common.IsHexAddress(s) {
				return nil, fmt.Errorf("invalid signer address %q for source chain %d", s, c.SourceChainSelector)
			}
			signers = append(signers, common.HexToAddress(s))
		}
		sigConfigs = append(sigConfigs, committee_verifier.SignatureConfig{
			SourceChainSelector: c.SourceChainSelector,
			Threshold:           c.Threshold,
			Signers:             signers,
		})
	}

	return writeCommitteeVerifier(env, destChainSelector, qualifier, committee_verifier.ApplySignatureConfigs,
		committee_verifier.ApplySignatureConfigsArgs{
			SourceChainSelectorsToRemove: change.RemovedSourceChainSelectors,
			SignatureConfigs:             sigConfigs,
		})
}

func (a *EVMCCVCommitteeVerifierOnchainAdapter) SetAllowedFinalityConfig(
	_ context.Context,
	env deployment.Environment,
	chainSelector uint64,
	qualifier string,
	waitForFinality bool,
	waitForSafe bool,
	blockDepth uint16,
) ([]mcmstypes.BatchOperation, error) {
	raw := finality.Config{
		WaitForFinality: waitForFinality,
		WaitForSafe:     waitForSafe,
		BlockDepth:      blockDepth,
	}.Raw()

	return writeCommitteeVerifier(env, chainSelector, qualifier, committee_verifier.SetAllowedFinalityConfig, raw)
}

func (a *EVMCCVCommitteeVerifierOnchainAdapter) ApplyAllowlistUpdates(
	_ context.Context,
	env deployment.Environment,
	chainSelector uint64,
	qualifier string,
	destChainSelector uint64,
	allowlistEnabled bool,
	addedSenders []string,
	removedSenders []string,
) ([]mcmstypes.BatchOperation, error) {
	added, err := toEVMSenderAddresses(addedSenders, "added")
	if err != nil {
		return nil, err
	}
	removed, err := toEVMSenderAddresses(removedSenders, "removed")
	if err != nil {
		return nil, err
	}

	return writeCommitteeVerifier(env, chainSelector, qualifier, applyAllowlistUpdates,
		[]committee_verifier.AllowlistConfigArgs{{
			DestChainSelector:         destChainSelector,
			AllowlistEnabled:          allowlistEnabled,
			AddedAllowlistedSenders:   added,
			RemovedAllowlistedSenders: removed,
		}})
}

// applyAllowlistUpdates mirrors committee_verifier.ApplyAllowlistUpdates but, like the contract,
// also lets the allowlist admin execute directly instead of only the owner.
var applyAllowlistUpdates = contract.NewWrite(contract.WriteParams[[]committee_verifier.AllowlistConfigArgs, *committee_verifier.CommitteeVerifierContract]{
	Name:            "ccv-committee-verifier:apply-allowlist-updates",
	Version:         committee_verifier.Version,
	Description:     "Calls applyAllowlistUpdates on the CommitteeVerifier as owner or allowlist admin",
	ContractType:    committee_verifier.ContractType,
	ContractABI:     committee_verifier.CommitteeVerifierABI,
	NewContract:     committee_verifier.NewCommitteeVerifierContract,
	IsAllowedCaller: ownerOrAllowlistAdmin,
	Validate:        func([]committee_verifier.AllowlistConfigArgs) error { return nil },
	CallContract: func(c *committee_verifier.CommitteeVerifierContract, opts *bind.TransactOpts, args []committee_verifier.AllowlistConfigArgs) (*types.Transaction, error) {
		return c.ApplyAllowlistUpdates(opts, args)
	},
})

func ownerOrAllowlistAdmin(c *committee_verifier.CommitteeVerifierContract, opts *bind.CallOpts, caller common.Address, args []committee_verifier.AllowlistConfigArgs) (bool, error) {
	isOwner, err := contract.OnlyOwner(c, opts, caller, args)
	if err != nil || isOwner {
		return isOwner, err
	}
	cfg, err := c.GetDynamicConfig(opts)
	if err != nil {
		return false, fmt.Errorf("failed to get dynamic config of %s: %w", c.Address(), err)
	}
	return cfg.AllowlistAdmin == caller, nil
}

// writeCommitteeVerifier runs a CommitteeVerifier write: mined directly when the deployer key
// is an allowed caller (no batch ops), otherwise returned as one MCMS batch op.
func writeCommitteeVerifier[ARGS any](
	env deployment.Environment,
	chainSelector uint64,
	qualifier string,
	op *cldfops.Operation[contract.FunctionInput[ARGS], contract.WriteOutput, evm.Chain],
	args ARGS,
) ([]mcmstypes.BatchOperation, error) {
	chain, ok := env.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return nil, fmt.Errorf("EVM chain %d not found in environment", chainSelector)
	}
	addr, err := committeeVerifierAddress(env, chainSelector, qualifier)
	if err != nil {
		return nil, err
	}

	// Force execution so a repeated config change in one bundle is not served from cache.
	report, err := cldfops.ExecuteOperation(
		env.OperationsBundle, op, chain,
		contract.FunctionInput[ARGS]{ChainSelector: chainSelector, Address: addr, Args: args},
		cldfops.WithForceExecute[contract.FunctionInput[ARGS], evm.Chain](),
	)
	if err != nil {
		return nil, fmt.Errorf("%s on CommitteeVerifier %s chain %d: %w", op.ID(), addr, chainSelector, err)
	}

	batchOp, err := contract.NewBatchOperationFromWrites([]contract.WriteOutput{report.Output})
	if err != nil {
		return nil, fmt.Errorf("failed to build batch operation for chain %d: %w", chainSelector, err)
	}
	if len(batchOp.Transactions) == 0 {
		return nil, nil
	}
	return []mcmstypes.BatchOperation{batchOp}, nil
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
