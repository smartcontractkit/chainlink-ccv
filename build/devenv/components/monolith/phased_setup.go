package monolith

import (
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// PhasedSetup carries all state produced by the protocol_contracts Phase 3 component
// so that runPhasedEnvironmentFinish (called from legacy Phase 4) can complete the
// environment without re-deriving it.
type PhasedSetup struct {
	In                *Cfg
	E                 *deployment.Environment
	Topology          *ccvdeployment.EnvironmentTopology
	SharedTLSCerts    *services.TLSCertPaths
	BlockchainOutputs []*blockchain.Output
	Selectors         []uint64
	DS                datastore.MutableDataStore
	Impls             []cciptestinterfaces.CCIP17Configuration
	FakeOut           *services.FakeOutput
	TimeTrack         *TimeTracker
}
