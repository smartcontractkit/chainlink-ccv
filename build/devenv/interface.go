package ccv

import (
	"context"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ccvTypes "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	nodeset "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

/*
This package contains interfaces for devenv to load chain-specific product implementations
Since 1.6/1.7 CCIP versions are incompatible for the time being we'll have 2 sets of interfaces that are mostly common
for CCIP16 and CCIP17
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

// Observable pushes Loki streams and exposes Prometheus metrics and returns queries to assert SLAs
type Observable interface {
	ExposeMetrics(ctx context.Context, addresses []string, chainIDs []string, wsURLs []string) ([]string, *prometheus.Registry, error)
}

// Testable provides functions for a standardized CCIP test suite.
type Testable interface {
	// SendArgsV2Message sends a message with ArgsV2 params
	SendArgsV2Message(ctx context.Context, e *deployment.Environment, addresses []string, src, dest uint64) error
	// SendArgsV3Message sends a message with ArgsV3 params
	SendArgsV3Message(ctx context.Context, e *deployment.Environment, addresses []string, selectors []uint64, src, dest uint64, finality uint16, execAddr string, execArgs, tokenArgs []byte, ccv, optCcv []ccvTypes.CCV, threshold uint8) error
	// GetExpectedNextSequenceNumber gets an expected sequence number for message with "from" and "to" selectors
	GetExpectedNextSequenceNumber(ctx context.Context, c any, from, to uint64) (uint64, error)
	// WaitOneSentEventBySeqNo waits until exactly one event for CCIP message sent is emitted on-chain
	WaitOneSentEventBySeqNo(ctx context.Context, contracts any, from, to uint64, seq uint64, timeout time.Duration) (any, error)
	// WaitOneExecEventBySeqNo waits until exactly one event for CCIP execution state change is emitted on-chain
	WaitOneExecEventBySeqNo(ctx context.Context, contracts any, from, to uint64, seq uint64, timeout time.Duration) (any, error)
}

// OnChainConfigurable defines methods that allows devenv to
// deploy, configure Chainlink product and connect on-chain part with other chains
type OnChainConfigurable interface {
	// DeployContractsForSelector configures contracts for chain X
	// returns all the contract addresses and metadata as datastore.DataStore
	DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64) (datastore.DataStore, error)
	// ConnectContractsWithSelectors connects this chain onRamp to one or multiple offRamps for remote selectors (other chains)
	ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64) error
}

// OffChainConfigurable defines methods that allows to
// deploy a local blockchain network for tests and configure CL nodes for Chainlink product
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
