package evm

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	bnm_drip_v1_0 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	bnm_drip_v1_5 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// TokenRefForPool maps a token pool address ref to the token address ref stored
// in the datastore. This mirrors TokenRef in buildEVMTokenTransferConfig.
//
// Generic devenv token expansion (BurnMint/LockRelease pools at 1.6.1 or 2.0.0)
// deploys bnm_drip v1.0.0 keyed by pool qualifier. Bespoke tokens such as Lombard
// use burn_mint_erc20_with_drip v1.5.0 with a fixed qualifier.
func TokenRefForPool(poolRef datastore.AddressRef) (datastore.AddressRef, error) {
	if poolRef.Qualifier == devenvcommon.LombardContractsQualifier {
		return datastore.AddressRef{
			Type:      datastore.ContractType(bnm_drip_v1_5.ContractType),
			Version:   semver.MustParse(bnm_drip_v1_5.Deploy.Version()),
			Qualifier: devenvcommon.LombardContractsQualifier,
		}, nil
	}

	switch string(poolRef.Type) {
	case devenvcommon.BurnMintTokenPoolType, devenvcommon.LockReleaseTokenPoolType:
		return datastore.AddressRef{
			Type:      datastore.ContractType(bnm_drip_v1_0.ContractType),
			Version:   semver.MustParse(bnm_drip_v1_0.Deploy.Version()),
			Qualifier: poolRef.Qualifier,
		}, nil
	default:
		return datastore.AddressRef{}, fmt.Errorf("no token mapping for pool type %s version %s", poolRef.Type, poolRef.Version)
	}
}
