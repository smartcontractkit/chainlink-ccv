package deploy

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	mcms_ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
)

// ultraFastCurseTimelockPlaceholder stands in for the Ultra Fast Curse MCMS timelock on EVM chains
// in the devenv.
//
// Deploying EVM chain contracts resolves this timelock and passes it to the RMN as its curse admin.
// The deploy sequence requires one unconditionally - including when DeployerKeyOwned is set, as the
// devenv does - but it only ever uses the address as a constructor argument and never calls it. The
// devenv has no MCMS infrastructure and nothing in it exercises RMN cursing, so a fixed non-zero
// placeholder is used rather than standing up a real MCMS. The address must be non-zero because
// AuthorizedCallers rejects the zero address.
//
// If the devenv ever needs a working curse admin, this is the seam to replace with a real MCMS
// deployment.
var ultraFastCurseTimelockPlaceholder = common.HexToAddress("0x00000000000000000000000000000000000c0e5e")

// SeedUltraFastCurseTimelock records the placeholder Ultra Fast Curse timelock for an EVM chain so
// that the chain-contract deploy can resolve it. It is a no-op for non-EVM families, which have no
// such requirement.
//
// The ref is matched on (chain selector, RBACTimelock, MCMS version, UltraFastCurse qualifier), so
// all four must line up with what the deploy sequence looks up.
func SeedUltraFastCurseTimelock(ds *datastore.MemoryDataStore, selector uint64, family string) error {
	if family != chainsel.FamilyEVM {
		return nil
	}

	ref := datastore.AddressRef{
		ChainSelector: selector,
		Type:          datastore.ContractType(cciputils.RBACTimelock),
		Version:       mcms_ops.MCMSVersion,
		Qualifier:     cciputils.UltraFastCurseMCMSQualifier,
		Address:       ultraFastCurseTimelockPlaceholder.Hex(),
	}
	if err := ds.Addresses().Add(ref); err != nil {
		return fmt.Errorf("seed ultra fast curse timelock for selector %d: %w", selector, err)
	}

	return nil
}
