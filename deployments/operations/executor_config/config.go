package executor_config

import (
	"fmt"
	"strconv"

	"github.com/Masterminds/semver/v3"

	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// ExecutorChainConfig contains the per-chain configuration for the executor.
type ExecutorChainConfig struct {
	OffRampAddress         string `json:"off_ramp_address"`
	RmnAddress             string `json:"rmn_address"`
	DefaultExecutorAddress string `json:"default_executor_address"`
}

// ExecutorGeneratedConfig contains the contract addresses resolved from the datastore.
type ExecutorGeneratedConfig struct {
	ChainConfigs map[string]ExecutorChainConfig `json:"chain_configs"`
}

// BuildConfigInput contains the input parameters for building the executor config.
type BuildConfigInput struct {
	ExecutorQualifier string
	ChainSelectors    []uint64
}

// BuildConfigOutput contains the generated executor configuration.
type BuildConfigOutput struct {
	Config *ExecutorGeneratedConfig
}

// BuildConfigDeps contains the dependencies for building the executor config.
type BuildConfigDeps struct {
	Env deployment.Environment
}

// BuildConfig is an operation that generates the executor configuration
// by querying the datastore for contract addresses.
var BuildConfig = operations.NewOperation(
	"build-executor-config",
	semver.MustParse("1.0.0"),
	"Builds the executor configuration from datastore contract addresses",
	func(b operations.Bundle, deps BuildConfigDeps, input BuildConfigInput) (BuildConfigOutput, error) {
		ds := deps.Env.DataStore

		chainConfigs := make(map[string]ExecutorChainConfig)

		for _, chainSelector := range input.ChainSelectors {
			chainSelectorStr := strconv.FormatUint(chainSelector, 10)

			offRampAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, "", offrampoperations.ContractType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get off ramp address for chain %d: %w", chainSelector, err)
			}

			rmnRemoteAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, "", rmn_remote.ContractType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get rmn remote address for chain %d: %w", chainSelector, err)
			}

			executorAddr, err := shared.ResolveContractAddress(
				ds, chainSelector, input.ExecutorQualifier, execcontract.ProxyType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get executor proxy address for chain %d: %w", chainSelector, err)
			}

			chainConfigs[chainSelectorStr] = ExecutorChainConfig{
				OffRampAddress:         offRampAddr,
				RmnAddress:             rmnRemoteAddr,
				DefaultExecutorAddress: executorAddr,
			}
		}

		return BuildConfigOutput{
			Config: &ExecutorGeneratedConfig{
				ChainConfigs: chainConfigs,
			},
		}, nil
	},
)
