package evm

import (
	"fmt"
	"math/big"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	rmn_remote "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	executorops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	fee_quoter "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/fee_quoter"
	offramp "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/offramp"
	onramp "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// EVMProtocolContractsDeployAdapter is a TESTING wrapper that implements
// ccvdeploymentadapters.ProtocolContractsDeployAdapter for EVM chains by
// proxying to the existing sequences.DeployChainContracts EVM sequence — the
// same sequence chainlink-ccip's own EVMDeployChainContractsAdapter drives.
//
// It exists in this repo so the chain-agnostic DeployProtocolContracts
// changeset can be exercised against a real EVM chain without first landing an
// implementation in chainlink-ccip. Delete it once the real adapter is
// registered in chainlink-ccip's chains/evm init().
type EVMProtocolContractsDeployAdapter struct{}

var _ ccvdeploymentadapters.ProtocolContractsDeployAdapter = (*EVMProtocolContractsDeployAdapter)(nil)

// EVMProtocolDeployExtrasKey is the FamilyExtras map key under which an
// EVMProtocolDeployExtras value may be supplied to override executor/on-ramp
// defaults. Optional — absent or wrong-typed values fall back to defaults.
const EVMProtocolDeployExtrasKey = "evm"

// EVMProtocolDeployExtras carries optional EVM-specific overrides. The
// chain-agnostic ProtocolContractsDeployInput intentionally omits these, so
// the wrapper applies sane defaults when they are not provided.
type EVMProtocolDeployExtras struct {
	// ExecutorFeeAggregator is applied to both the executor dynamic config and
	// the OnRamp fee aggregator. Zero address leaves both unset.
	ExecutorFeeAggregator common.Address
	// MaxCCVsPerMsg defaults to 10 when zero.
	MaxCCVsPerMsg uint8
	// CcvAllowlistEnabled defaults to false.
	CcvAllowlistEnabled bool
	// AllowedFinality defaults to finality.Config{BlockDepth: 1}.Raw() when zero.
	AllowedFinality [4]byte
}

var evmDeployProtocolContracts = cldf_ops.NewSequence(
	"evm-deploy-protocol-contracts",
	semver.MustParse("2.0.0"),
	"Testing wrapper around the EVM DeployChainContracts sequence (protocol contracts only)",
	func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, in ccvdeploymentadapters.ProtocolContractsDeployInput) (ccvdeploymentadapters.ProtocolContractsDeployOutput, error) {
		evmChain, ok := chains.EVMChains()[in.ChainSelector]
		if !ok {
			return ccvdeploymentadapters.ProtocolContractsDeployOutput{},
				fmt.Errorf("EVM chain not found for selector %d", in.ChainSelector)
		}

		evmInput, err := toEVMProtocolDeployInput(in)
		if err != nil {
			return ccvdeploymentadapters.ProtocolContractsDeployOutput{}, err
		}

		report, err := cldf_ops.ExecuteSequence(b, sequences.DeployChainContracts, evmChain, evmInput)
		if err != nil {
			return ccvdeploymentadapters.ProtocolContractsDeployOutput{},
				fmt.Errorf("EVM DeployChainContracts failed: %w", err)
		}

		return ccvdeploymentadapters.ProtocolContractsDeployOutput{
			// Addresses and BatchOps are promoted from the embedded OnChainOutput.
			Addresses:               report.Output.Addresses,
			BatchOps:                report.Output.BatchOps,
			RefsToTransferOwnership: report.Output.RefsToTransferOwnership,
		}, nil
	})

// DeployProtocolContracts returns the chain-agnostic wrapper sequence.
func (a *EVMProtocolContractsDeployAdapter) DeployProtocolContracts() *cldf_ops.Sequence[
	ccvdeploymentadapters.ProtocolContractsDeployInput,
	ccvdeploymentadapters.ProtocolContractsDeployOutput,
	cldf_chain.BlockChains,
] {
	return evmDeployProtocolContracts
}

// RegisterEVMProtocolContractsDeployAdapter registers this adapter for the EVM
// chain family. Idempotent: the registry overwrites any existing entry. It is
// called from init() for devenv convenience and is also exported so focused
// tests can register explicitly.
func RegisterEVMProtocolContractsDeployAdapter() {
	ccvdeploymentadapters.GetProtocolContractsDeployRegistry().
		Register(chainsel.FamilyEVM, &EVMProtocolContractsDeployAdapter{})
}

func init() {
	RegisterEVMProtocolContractsDeployAdapter()
}

// toEVMProtocolDeployInput converts the chain-agnostic ProtocolContractsDeployInput
// into the richer EVM-specific sequences.DeployChainContractsInput, filling in
// the contract versions and static config the chain-agnostic shape omits.
func toEVMProtocolDeployInput(in ccvdeploymentadapters.ProtocolContractsDeployInput) (sequences.DeployChainContractsInput, error) {
	if !common.IsHexAddress(in.DeployerContract) {
		return sequences.DeployChainContractsInput{},
			fmt.Errorf("DeployerContract %q is not a valid hex address", in.DeployerContract)
	}
	create2Factory := common.HexToAddress(in.DeployerContract)

	extras := resolveEVMExtras(in.FamilyExtras)
	executors := buildExecutorParams(in.Executors, extras)

	return sequences.DeployChainContractsInput{
		ChainSelector:     in.ChainSelector,
		CREATE2Factory:    create2Factory,
		ExistingAddresses: in.ExistingAddresses,
		DeployTestRouter:  in.DeployTestRouter,
		// Testing-wrapper constraint: force DeployerKeyOwned=true. The ccv
		// changeset only consumes report.Output.Addresses and drops BatchOps /
		// RefsToTransferOwnership, so any ownership-transfer work the sequence
		// would produce (and the timelocks it would require in ExistingAddresses)
		// would be silently discarded. Forcing true skips that path entirely.
		DeployerKeyOwned: true,
		ContractParams: sequences.ContractParams{
			RMNRemote: sequences.RMNRemoteParams{
				Version: rmn_remote.Version,
			},
			OffRamp: sequences.OffRampParams{
				Version:                   offramp.Version,
				GasForCallExactCheck:      5_000,
				MaxGasBufferToUpdateState: 12_000,
			},
			OnRamp: sequences.OnRampParams{
				Version:               onramp.Version,
				FeeAggregator:         extras.ExecutorFeeAggregator,
				MaxUSDCentsPerMessage: 100_00, // 100.00 USD
			},
			FeeQuoter: sequences.FeeQuoterParams{
				Version:                        fee_quoter.Version,
				MaxFeeJuelsPerMsg:              new(big.Int).Mul(big.NewInt(2e2), big.NewInt(1e18)),
				LINKPremiumMultiplierWeiPerEth: 9e17,                                 // 0.9 ETH
				WETHPremiumMultiplierWeiPerEth: 1e18,                                 // 1.0 ETH
				USDPerLINK:                     mustBigInt("15000000000000000000"),   // $15
				USDPerWETH:                     mustBigInt("2000000000000000000000"), // $2000
			},
			// Committee verifiers are deployed separately (DeployCommitteeVerifier).
			CommitteeVerifiers: nil,
			// Mock receivers are intentionally omitted: the default mock receiver
			// references a CommitteeVerifierResolver that this flow never deploys,
			// which would fail verifier resolution in the sequence.
			MockReceivers: nil,
			Executors:     executors,
		},
	}, nil
}

// resolveEVMExtras reads optional overrides from FamilyExtras, applying defaults
// for any unset field.
func resolveEVMExtras(familyExtras map[string]any) EVMProtocolDeployExtras {
	extras := EVMProtocolDeployExtras{}
	if familyExtras != nil {
		if v, ok := familyExtras[EVMProtocolDeployExtrasKey].(EVMProtocolDeployExtras); ok {
			extras = v
		}
	}
	if extras.MaxCCVsPerMsg == 0 {
		extras.MaxCCVsPerMsg = 10
	}
	if extras.AllowedFinality == ([4]byte{}) {
		extras.AllowedFinality = finality.Config{BlockDepth: 1}.Raw()
	}
	return extras
}

// buildExecutorParams maps the chain-agnostic executor params (Qualifier +
// Version only) to the EVM-specific shape, filling dynamic-config fields from
// the resolved extras.
func buildExecutorParams(
	params []ccvdeploymentadapters.ExecutorDeployParams,
	extras EVMProtocolDeployExtras,
) []sequences.ExecutorParams {
	result := make([]sequences.ExecutorParams, 0, len(params))
	for _, ep := range params {
		result = append(result, sequences.ExecutorParams{
			Version:       ep.Version,
			MaxCCVsPerMsg: extras.MaxCCVsPerMsg,
			DynamicConfig: executorops.DynamicConfig{
				FeeAggregator:         extras.ExecutorFeeAggregator,
				AllowedFinalityConfig: extras.AllowedFinality,
				CcvAllowlistEnabled:   extras.CcvAllowlistEnabled,
			},
			Qualifier: ep.Qualifier,
		})
	}
	return result
}

func mustBigInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("invalid big.Int constant %q", s))
	}
	return v
}
