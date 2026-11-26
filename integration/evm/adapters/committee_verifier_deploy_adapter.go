package adapters

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	cldfchain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldfops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/rmn_proxy"
	mcms_seq "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	common_utils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// EVMCommitteeVerifierDeployAdapter implements
// ccvdeploymentadapters.CommitteeVerifierDeployAdapter for EVM chains by
// proxying to the existing sequences.DeployCommitteeVerifier sequence. It
// converts the chain-agnostic input shape into the EVM-specific input,
// resolving the RMNProxy address from the caller-supplied existing
// addresses.
type EVMCommitteeVerifierDeployAdapter struct{}

var _ ccvdeploymentadapters.CommitteeVerifierDeployAdapter = (*EVMCommitteeVerifierDeployAdapter)(nil)

var evmDeployCommitteeVerifier = cldfops.NewSequence(
	"evm-deploy-committee-verifier",
	semver.MustParse("2.0.0"),
	"Chain-agnostic wrapper around the EVM DeployCommitteeVerifier sequence",
	func(b cldfops.Bundle, chains cldfchain.BlockChains, input ccvdeploymentadapters.CommitteeVerifierDeployInput) (ccvdeploymentadapters.CommitteeVerifierDeployOutput, error) {
		evmChains := chains.EVMChains()
		evmChain, ok := evmChains[input.ChainSelector]
		if !ok {
			return ccvdeploymentadapters.CommitteeVerifierDeployOutput{},
				fmt.Errorf("EVM chain not found for selector %d", input.ChainSelector)
		}

		create2Factory, err := parseRequiredHexAddress(input.DeployerContract, "DeployerContract")
		if err != nil {
			return ccvdeploymentadapters.CommitteeVerifierDeployOutput{}, err
		}

		rmnAddr, err := resolveRMNProxyAddress(input.ExistingAddresses, input.ChainSelector)
		if err != nil {
			return ccvdeploymentadapters.CommitteeVerifierDeployOutput{}, err
		}

		feeAgg, err := parseRequiredNonZeroHexAddress(
			input.Params.FeeAggregator,
			fmt.Sprintf("committee %q FeeAggregator", input.Params.Qualifier),
		)
		if err != nil {
			return ccvdeploymentadapters.CommitteeVerifierDeployOutput{}, err
		}

		var allowlistAdmin common.Address
		if input.Params.AllowlistAdmin != "" {
			allowlistAdmin, err = parseHexAddress(
				input.Params.AllowlistAdmin,
				fmt.Sprintf("committee %q AllowlistAdmin", input.Params.Qualifier),
			)
			if err != nil {
				return ccvdeploymentadapters.CommitteeVerifierDeployOutput{}, err
			}
		}

		evmInput := sequences.DeployCommitteeVerifierInput{
			ChainSelector:     input.ChainSelector,
			ExistingAddresses: input.ExistingAddresses,
			CREATE2Factory:    create2Factory,
			RMN:               rmnAddr,
			Params: sequences.CommitteeVerifierParams{
				Version:          input.Params.Version,
				AllowlistAdmin:   allowlistAdmin,
				FeeAggregator:    feeAgg,
				StorageLocations: input.Params.StorageLocations,
				Qualifier:        input.Params.Qualifier,
			},
		}

		report, err := cldfops.ExecuteSequence(b, sequences.DeployCommitteeVerifier, evmChain, evmInput)
		if err != nil {
			return ccvdeploymentadapters.CommitteeVerifierDeployOutput{},
				fmt.Errorf("EVM DeployCommitteeVerifier failed: %w", err)
		}

		out := ccvdeploymentadapters.CommitteeVerifierDeployOutput{
			Addresses: report.Output.Addresses,
			BatchOps:  report.Output.BatchOps,
		}
		if !input.DeployerKeyOwned {
			timelock, err := resolveCLLTimelockAddress(input.ExistingAddresses, input.ChainSelector)
			if err != nil {
				return ccvdeploymentadapters.CommitteeVerifierDeployOutput{}, err
			}
			for _, ref := range report.Output.Addresses {
				owner, _, err := mcms_seq.LoadOwnableContract(common.HexToAddress(ref.Address), evmChain.Client)
				if err != nil {
					return ccvdeploymentadapters.CommitteeVerifierDeployOutput{},
						fmt.Errorf("failed to load owner of %s at %s: %w", ref.Type, ref.Address, err)
				}
				if owner != timelock {
					out.RefsToTransferOwnership = append(out.RefsToTransferOwnership, ref)
				}
			}
		}
		return out, nil
	},
)

func (a *EVMCommitteeVerifierDeployAdapter) DeployCommitteeVerifier() *cldfops.Sequence[ccvdeploymentadapters.CommitteeVerifierDeployInput, ccvdeploymentadapters.CommitteeVerifierDeployOutput, cldfchain.BlockChains] {
	return evmDeployCommitteeVerifier
}

// resolveRMNProxyAddress finds the RMNProxy (ARMProxy contract type) on the
// given chain in existingAddresses. The EVM CommitteeVerifier constructor
// requires this address, so callers must ensure the proxy is already
// deployed when invoking the standalone CCV deploy.
func resolveRMNProxyAddress(existingAddresses []datastore.AddressRef, chainSelector uint64) (common.Address, error) {
	for _, ref := range existingAddresses {
		if ref.ChainSelector != chainSelector {
			continue
		}
		if ref.Type != datastore.ContractType(rmn_proxy.ContractType) {
			continue
		}
		if ref.Version == nil || !ref.Version.Equal(rmn_proxy.Version) {
			continue
		}
		if !common.IsHexAddress(ref.Address) {
			return common.Address{}, fmt.Errorf("RMNProxy address %q on chain %d is not a valid hex address", ref.Address, chainSelector)
		}
		return common.HexToAddress(ref.Address), nil
	}
	return common.Address{}, fmt.Errorf("RMNProxy (type=%s version=%s) not found in ExistingAddresses for chain %d", rmn_proxy.ContractType, rmn_proxy.Version, chainSelector)
}

// resolveCLLTimelockAddress returns the CLLCCIP RBAC timelock on chainSelector,
// the owner committee verifiers are handed to.
func resolveCLLTimelockAddress(existingAddresses []datastore.AddressRef, chainSelector uint64) (common.Address, error) {
	var found []string
	for _, ref := range existingAddresses {
		if ref.ChainSelector == chainSelector &&
			ref.Type == datastore.ContractType(common_utils.RBACTimelock) &&
			ref.Qualifier == common_utils.CLLQualifier {
			found = append(found, ref.Address)
		}
	}
	if len(found) != 1 {
		return common.Address{}, fmt.Errorf("expected one %s RBACTimelock on chain %d, found %d: deploy MCMS first, or set DeployerKeyOwned",
			common_utils.CLLQualifier, chainSelector, len(found))
	}
	if !common.IsHexAddress(found[0]) {
		return common.Address{}, fmt.Errorf("RBACTimelock address %q on chain %d is not a valid hex address", found[0], chainSelector)
	}
	return common.HexToAddress(found[0]), nil
}
