package ccv

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"

	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

// convertTopologyToCCIP converts ccvdeployment.EnvironmentTopology to the
// ccipOffchain.EnvironmentTopology required by onchain changesets in chainlink-ccip
// that have not yet migrated to the ccv deployment package. Phase 2 bridge shim.
func convertTopologyToCCIP(src *ccvdeployment.EnvironmentTopology) *ccipOffchain.EnvironmentTopology {
	if src == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(src); err != nil {
		panic(fmt.Sprintf("convertTopologyToCCIP encode: %v", err))
	}
	var dst ccipOffchain.EnvironmentTopology
	if _, err := toml.Decode(buf.String(), &dst); err != nil {
		panic(fmt.Sprintf("convertTopologyToCCIP decode: %v", err))
	}
	return &dst
}
