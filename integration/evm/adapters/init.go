package adapters

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func init() {
	// EVM chain-type and address registration for the ccv deployment layer.
	shared.RegisterChainTypeFamily(nodev1.ChainType_CHAIN_TYPE_EVM, chainsel.FamilyEVM)
	shared.RegisterAddressNormalizer(chainsel.FamilyEVM, func(addr string) string {
		lower := strings.ToLower(addr)
		if !strings.HasPrefix(lower, "0x") {
			return "0x" + lower
		}
		return lower
	})

	// Register all EVM ccv adapter implementations into the ccv singleton registries.
	ccvdeploymentadapters.GetAggregatorRegistry().Register(chainsel.FamilyEVM, &EVMCCVAggregatorConfigAdapter{})
	ccvdeploymentadapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &EVMCCVExecutorConfigAdapter{})
	ccvdeploymentadapters.GetVerifierRegistry().Register(chainsel.FamilyEVM, &EVMCCVVerifierConfigAdapter{})
	ccvdeploymentadapters.GetIndexerRegistry().Register(chainsel.FamilyEVM, &EVMCCVIndexerConfigAdapter{})
	ccvdeploymentadapters.GetTokenVerifierRegistry().Register(chainsel.FamilyEVM, &EVMCCVTokenVerifierConfigAdapter{})
	ccvdeploymentadapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyEVM, &EVMCCVCommitteeVerifierOnchainAdapter{})
	ccvdeploymentadapters.GetCommitteeVerifierDeployRegistry().Register(chainsel.FamilyEVM, &EVMCommitteeVerifierDeployAdapter{})
	ccvdeploymentadapters.GetProtocolContractsDeployRegistry().Register(chainsel.FamilyEVM, &EVMProtocolContractsDeployAdapter{})
}

func parseHexAddress(hex, field string) (common.Address, error) {
	if !common.IsHexAddress(hex) {
		return common.Address{}, fmt.Errorf("%s: %q is not a valid hex address", field, hex)
	}
	return common.HexToAddress(hex), nil
}

func parseRequiredHexAddress(hex, field string) (common.Address, error) {
	if hex == "" {
		return common.Address{}, fmt.Errorf("%s is required", field)
	}
	return parseHexAddress(hex, field)
}

func parseRequiredNonZeroHexAddress(hex, field string) (common.Address, error) {
	addr, err := parseRequiredHexAddress(hex, field)
	if err != nil {
		return common.Address{}, err
	}
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("%s cannot be zero address", field)
	}
	return addr, nil
}
