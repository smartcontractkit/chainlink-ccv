package devenv_common

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	nodeset "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

/*
This package contains interfaces that should be moved to chainlink-ccip.
Since 1.6/1.7 CCIP versions are incompatible for the time being we'll have 2 sets of interfaces that are mostly common
but exist in multiple repositories: chainlink-ccip (1.6) and chainlink-ccv (1.7)
*/

// CCIP17ProductConfiguration includes all the interfaces that if implemented allows us to run a standard test suite
// for at least 2 chains (EVM and Solana, for example).
type CCIP17ProductConfiguration interface {
	Testable
	OnChainConfigurable
	OffChainConfigurable
}

// Testable provides functions for a standardized CCIP test suite.
type Testable interface {
	// SendMessage called for a src network
	// sends message to a router that is connected to some other network
	SendMessage(ctx context.Context, router CommonAddress, msg UserMsg) (CommonMsgID, error)
	// VerifyMessage called for a dst network
	// verifies that the message is delivered
	VerifyMessage(ctx context.Context, offRamp CommonAddress, msg UserMsg, id CommonMsgID) error
}

// OnChainConfigurable defines methods that allows devenv to configure
// Chainlink products for a specific chain X connected with chain Y.
type OnChainConfigurable interface {
	// DeployContractsForSelector configures contracts for chain X
	// returns all the contract addresses and metadata
	DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64) (datastore.DataStore, error)
	// ConnectContractsWithSelector connects onRamp/offRamp contracts with selector Y
	ConnectContractsWithSelector(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64) error
}

type OffChainConfigurable interface {
	// DeployLocalNetwork deploy local node of network X
	DeployLocalNetwork(ctx context.Context, bcs *blockchain.Input) (*blockchain.Output, error)
	// ConfigureNodes configure CL nodes from blockchain data
	// returns a piece of TOML config as a string that the framework inject into final configuration
	ConfigureNodes(ctx context.Context, blockchain *blockchain.Input) (string, error)
	// FundNodes Fund Chainlink nodes for some amount of native/LINK currency
	// using chain-specific clients or CLDF
	FundNodes(ctx context.Context, cls []*nodeset.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error
}
