package verifier_config

import (
	"fmt"
	"strconv"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// VerifierGeneratedConfig contains the contract addresses resolved from the datastore.
type VerifierGeneratedConfig struct {
	CommitteeVerifierAddresses     map[string]string `json:"committee_verifier_addresses"`
	OnRampAddresses                map[string]string `json:"on_ramp_addresses"`
	DefaultExecutorOnRampAddresses map[string]string `json:"default_executor_on_ramp_addresses"`
	RMNRemoteAddresses             map[string]string `json:"rmn_remote_addresses"`
}

// BuildConfigInput contains the input parameters for building the verifier config.
type BuildConfigInput struct {
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
}

// BuildConfigOutput contains the generated verifier configuration.
type BuildConfigOutput struct {
	Config *VerifierGeneratedConfig
}

// BuildConfigDeps contains the dependencies for building the verifier config.
type BuildConfigDeps struct {
	Env deployment.Environment
}

// BuildConfig is an operation that generates the verifier configuration
// by querying the datastore for contract addresses.
var BuildConfig = operations.NewOperation(
	"build-verifier-config",
	semver.MustParse("1.0.0"),
	"Builds the verifier configuration from datastore contract addresses",
	func(b operations.Bundle, deps BuildConfigDeps, input BuildConfigInput) (BuildConfigOutput, error) {
		ds := deps.Env.DataStore

		committeeVerifierAddresses := make(map[string]string)
		onRampAddresses := make(map[string]string)
		defaultExecutorOnRampAddresses := make(map[string]string)
		rmnRemoteAddresses := make(map[string]string)

		for _, chainSelector := range input.ChainSelectors {
			chainSelectorStr := strconv.FormatUint(chainSelector, 10)

			committeeVerifierAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, input.CommitteeQualifier, committee_verifier.ResolverType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get committee verifier address for chain %d: %w", chainSelector, err)
			}
			committeeVerifierAddresses[chainSelectorStr] = committeeVerifierAddr

			onRampAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, "", onrampoperations.ContractType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get on ramp address for chain %d: %w", chainSelector, err)
			}
			onRampAddresses[chainSelectorStr] = onRampAddr

			executorAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, input.ExecutorQualifier, executor.ProxyType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get executor proxy address for chain %d: %w", chainSelector, err)
			}
			defaultExecutorOnRampAddresses[chainSelectorStr] = executorAddr

			rmnRemoteAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, "", rmn_remote.ContractType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get rmn remote address for chain %d: %w", chainSelector, err)
			}
			rmnRemoteAddresses[chainSelectorStr] = rmnRemoteAddr
		}

		return BuildConfigOutput{
			Config: &VerifierGeneratedConfig{
				CommitteeVerifierAddresses:     committeeVerifierAddresses,
				OnRampAddresses:                onRampAddresses,
				DefaultExecutorOnRampAddresses: defaultExecutorOnRampAddresses,
				RMNRemoteAddresses:             rmnRemoteAddresses,
			},
		}, nil
	},
)
