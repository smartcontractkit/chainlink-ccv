package evm

import (
	"encoding/json"
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/rmn_proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	ccv_aggregator_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccv_proxy_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	commit_offramp_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/commit_offramp"
	commit_onramp_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/commit_onramp"
	executor_onramp_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/executor_onramp"
	fee_quoter_v2_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/mock_receiver_v2"
	rmn_proxy_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_0_0/rmn_proxy_contract"
	router_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	token_admin_registry_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/token_admin_registry"
	rmn_remote_bindings "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

/*
	// RMNRemote
*/

type rawContractInfo struct {
	solidityStandardJSONInput string
	bytecode                  string
	name                      string
}

// contracts maps type & version of a contract to its corresponding standard JSON input, name, and bytecode.
// TODO: WETH & LINK?
var contracts map[cldf.ContractType]map[*semver.Version]rawContractInfo = map[cldf.ContractType]map[*semver.Version]rawContractInfo{
	ccv_aggregator.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: ccv_aggregator_bindings.SolidityStandardInput,
			bytecode:                  ccv_aggregator_bindings.CCVAggregatorBin,
			name:                      "contracts/offRamps/CCVAggregator.sol:CCVAggregator",
		},
	},
	ccv_proxy.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: ccv_proxy_bindings.SolidityStandardInput,
			bytecode:                  ccv_proxy_bindings.CCVProxyBin,
			name:                      "contracts/onRamps/CCVProxy.sol:CCVProxy",
		},
	},
	commit_onramp.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: commit_onramp_bindings.SolidityStandardInput,
			bytecode:                  commit_onramp_bindings.CommitOnRampBin,
			name:                      "contracts/onRamps/CommitOnRamp.sol:CommitOnRamp",
		},
	},
	commit_offramp.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: commit_offramp_bindings.SolidityStandardInput,
			bytecode:                  commit_offramp_bindings.CommitOffRampBin,
			name:                      "contracts/offRamps/CommitOffRamp.sol:CommitOffRamp",
		},
	},
	executor_onramp.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: executor_onramp_bindings.SolidityStandardInput,
			bytecode:                  executor_onramp_bindings.ExecutorOnRampBin,
			name:                      "contracts/onRamps/ExecutorOnRamp.sol:ExecutorOnRamp",
		},
	},
	mock_receiver.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: mock_receiver_v2.SolidityStandardInput,
			bytecode:                  mock_receiver_v2.MockReceiverV2Bin,
			name:                      "contracts/test/mocks/MockReceiverV2.sol:MockReceiverV2",
		},
	},
	fee_quoter_v2.ContractType: {
		semver.MustParse("1.7.0"): rawContractInfo{
			solidityStandardJSONInput: fee_quoter_v2_bindings.SolidityStandardInput,
			bytecode:                  fee_quoter_v2_bindings.FeeQuoterV2Bin,
			name:                      "contracts/FeeQuoterV2.sol:FeeQuoterV2",
		},
	},
	router.ContractType: {
		semver.MustParse("1.2.0"): rawContractInfo{
			solidityStandardJSONInput: router_bindings.SolidityStandardInput,
			bytecode:                  router_bindings.RouterBin,
			name:                      "contracts/Router.sol:Router",
		},
	},
	rmn_proxy.ContractType: {
		semver.MustParse("1.0.0"): rawContractInfo{
			solidityStandardJSONInput: rmn_proxy_bindings.SolidityStandardInput,
			bytecode:                  rmn_proxy_bindings.RMNProxyBin,
			name:                      "contracts/rmn/RMNProxy.sol:RMNProxy",
		},
	},
	token_admin_registry.ContractType: {
		semver.MustParse("1.5.0"): rawContractInfo{
			solidityStandardJSONInput: token_admin_registry_bindings.SolidityStandardInput,
			bytecode:                  token_admin_registry_bindings.TokenAdminRegistryBin,
			name:                      "contracts/tokenAdminRegistry/TokenAdminRegistry.sol:TokenAdminRegistry",
		},
	},
	rmn_remote.ContractType: {
		semver.MustParse("1.6.0"): rawContractInfo{
			solidityStandardJSONInput: rmn_remote_bindings.SolidityStandardInput,
			bytecode:                  rmn_remote_bindings.RMNRemoteBin,
			name:                      "contracts/rmn/RMNRemote.sol:RMNRemote",
		},
	},
}

// loadSolidityContractMetadata loads the metadata for a contract type and version, including the standard JSON input, bytecode, and name.
func loadSolidityContractMetadata(contractType cldf.ContractType, version *semver.Version) (solidityContractMetadata, error) {
	contract, ok := contracts[contractType]
	if !ok {
		return solidityContractMetadata{}, fmt.Errorf("no contract found for type %s", contractType)
	}
	contractWithVersion, ok := contract[version]
	if !ok {
		return solidityContractMetadata{}, fmt.Errorf("no contract found for type %s with version %s", contractType, version)
	}

	var input solidityContractMetadata
	err := json.Unmarshal([]byte(contractWithVersion.solidityStandardJSONInput), &input)
	if err != nil {
		return solidityContractMetadata{}, fmt.Errorf("failed to unmarshal solidity standard JSON input for contract type %s: %w", contractType, err)
	}
	// Add remaining fields that don't exist in the standard JSON input
	input.Bytecode = contractWithVersion.bytecode
	input.Name = contractWithVersion.name

	return input, nil
}

// solidityContractMetadata defines the metadata for a Solidity contract, including the standard JSON input, bytecode, and contract name.
type solidityContractMetadata struct {
	Version  string         `json:"version"`
	Language string         `json:"language"`
	Settings map[string]any `json:"settings"`
	Sources  map[string]any `json:"sources"`
	Bytecode string         `json:"bytecode"`
	Name     string         `json:"name"`
}

// SourceCode returns the source code of the contract as a string.
func (s solidityContractMetadata) SourceCode() (string, error) {
	sourceCodeMap := map[string]any{
		"language": s.Language,
		"settings": s.Settings,
		"sources":  s.Sources,
	}
	jsonBytes, err := json.Marshal(sourceCodeMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal source code: %w", err)
	}

	return string(jsonBytes), nil
}
