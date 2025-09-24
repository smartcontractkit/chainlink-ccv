package ccv

import (
	"context"
	"math/big"

	"github.com/prometheus/client_golang/prometheus"
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

// CCIP17ProductConfiguration includes all the interfaces that if implemented allows us to run a standard test suite for 2+ chains
// it deploys network-specific infrastructure, configures both CL nodes and contracts and returns
// operations for testing and SLA/Metrics assertions
type CCIP17ProductConfiguration interface {
	Testable
	Observable
	OnChainConfigurable
	OffChainConfigurable
}

// Observable exposes Loki and Prometheus metrics and returns queries to assert SLAs
type Observable interface {
	ExposeMetrics(ctx context.Context, addresses []string, chainIDs []string, wsURLs []string) ([]string, *prometheus.Registry, error)
}

// Testable provides functions for a standardized CCIP test suite.
type Testable interface {
	// SendMessage called for a src network
	// sends message to a router that is connected to some other network
	SendMessage(ctx context.Context, router string, msg []byte) ([]byte, error)
	// VerifyMessage called for a dst network
	// verifies that the message is delivered
	VerifyMessage(ctx context.Context, offRamp string, msg []byte, id []byte) error
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
