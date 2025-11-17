package constructors

import (
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

// CCVProvider is a work in progress! It will eventually become the chain agnostic interface implemented
// by all chain families to support the Committee Verifier and Executor services. For now it reflects
// the EVM-Centric nature of the initial implementation and is a simple downcast of the legacyevm.Chain
// object.
//
// Note: many of the  chainlink-evm objects used here already have a generic interface in the
// chainlink-frameworks library. The way generics are used prevents us from using them in a polymorphic way.
// This means some sort of adapter will be required for each chain type we want to support.
// Until that adapter interface exists, we only support EVM.
//
// Next steps:
// - Identify the full set of functions required by client.Client, heads.Tracker and txmg.TxManager
// - Redefine those functions in this interface, using protocol types where possible.
// - Create an adapter layer for legacyevm.Chain that implements this interface.
// - Define a LOOPP client for this interface.
type CCVProvider interface {
	Client() client.Client      // verifier, executor
	HeadTracker() heads.Tracker // verifier
	TxManager() txmgr.TxManager // executor
}
