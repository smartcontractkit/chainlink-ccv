package cciptestinterfaces

import (
	"context"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
// operations for testing and SLA/Metrics assertions.
type CCIP17ProductConfiguration interface {
	Chains
	Observable
	OnChainConfigurable
	OffChainConfigurable
}

// Observable pushes Loki streams and exposes Prometheus metrics and returns queries to assert SLAs.
type Observable interface {
	// ExposeMetrics exposes Prometheus metrics for the given source and destination chain IDs.
	ExposeMetrics(ctx context.Context, source, dest uint64, chainIDs, wsURLs []string) ([]string, *prometheus.Registry, error)
}

// TokenAmount represents a token amount being sent in a CCIP message.
type TokenAmount struct {
	// Amount of tokens to send.
	Amount *big.Int
	// TokenAddress of the token on the source chain.
	TokenAddress protocol.UnknownAddress
}

// MessageFields consist of the non-extraArgs part of the CCIP message.
// These are typically always specified by the caller whereas extraArgs
// may not be.
type MessageFields struct {
	// Receiver is the receiver address for the message on the destination chain.
	// This is required.
	Receiver protocol.UnknownAddress
	// Data is the data for the message
	// This is required.
	Data []byte
	// TokenAmounts are the token amounts for the message.
	// This is optional - the default means no tokens are sent.
	TokenAmounts []TokenAmount
	// FeeToken is the fee token to pay in.
	// This is optional - the default means native token is used.
	FeeToken protocol.UnknownAddress
}

// MessageOptions consists of all the ways one can modify a CCIP message
// using extraArgs.
type MessageOptions struct {
	// Version indicates the version of the extraArgs.
	Version uint8
	// GasLimit is the gas limit for the message
	// Equivalent to ComputeLimit for solana.
	GasLimit uint32
	// OutOfOrderExecution is whether to execute the message out of order
	OutOfOrderExecution bool
	// CCVs are the CCVs for the message
	CCVs []protocol.CCV
	// FinalityConfig is the finality config for the message
	FinalityConfig uint16
	// Executor is the executor address
	Executor protocol.UnknownAddress
	// ExecutorArgs are the executor arguments for the message
	ExecutorArgs []byte
	// TokenArgs are the token arguments for the message
	TokenArgs []byte
}

// MessageSentEvent is a chain-agnostic representation of the output of a ccipSend operation.
type MessageSentEvent struct {
	MessageID      [32]byte
	SequenceNumber uint64
	Message        *protocol.Message
	ReceiptIssuers []protocol.UnknownAddress
	VerifierBlobs  [][]byte
}

// MessageExecutionState represents the execution state of a CCIP message.
// This must be the same across all implementations of CCIP on all chain families.
type MessageExecutionState uint8

const (
	ExecutionStateUntouched MessageExecutionState = iota
	ExecutionStateInProgress
	ExecutionStateSuccess
	ExecutionStateFailure
)

// ExecutionStateChangedEvent is a chain-agnostic representation of the output of a ccip message execution operation.
type ExecutionStateChangedEvent struct {
	MessageID      [32]byte
	SequenceNumber uint64
	State          MessageExecutionState
	ReturnData     []byte
}

// Chains provides methods to interact with a set of chains that have CCIP deployed.
type Chains interface {
	// GetEOAReceiverAddress gets an EOA receiver address for the provided chain selector.
	GetEOAReceiverAddress(chainSelector uint64) (protocol.UnknownAddress, error)
	// GetSenderAddress gets the sender address for the provided chain selector.
	GetSenderAddress(chainSelector uint64) (protocol.UnknownAddress, error)
	// SendMessage sends a CCIP message from src to dest with the specified message options.
	SendMessage(ctx context.Context, src, dest uint64, fields MessageFields, opts MessageOptions) (MessageSentEvent, error)
	// GetExpectedNextSequenceNumber gets an expected sequence number for message with "from" and "to" selectors
	GetExpectedNextSequenceNumber(ctx context.Context, from, to uint64) (uint64, error)
	// WaitOneSentEventBySeqNo waits until exactly one event for CCIP message sent is emitted on-chain
	WaitOneSentEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (MessageSentEvent, error)
	// WaitOneExecEventBySeqNo waits until exactly one event for CCIP execution state change is emitted on-chain
	WaitOneExecEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (ExecutionStateChangedEvent, error)
	// GetTokenBalance gets the balance of an account for a token on a chain
	GetTokenBalance(ctx context.Context, chainSelector uint64, address, tokenAddress protocol.UnknownAddress) (*big.Int, error)
	// GetMaxDataBytes gets the maximum data size for a CCIP message to a remote chain.
	GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error)
}

type OnChainCommittees struct {
	CommitteeQualifier string
	Signers            [][]byte
	Threshold          uint8
}

// OnChainConfigurable defines methods that allows devenv to
// deploy, configure Chainlink product and connect on-chain part with other chains.
type OnChainConfigurable interface {
	// DeployContractsForSelector configures contracts for chain X
	// returns all the contract addresses and metadata as datastore.DataStore
	DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees []OnChainCommittees) (datastore.DataStore, error)
	// ConnectContractsWithSelectors connects this chain onRamp to one or multiple offRamps for remote selectors (other chains)
	ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees []OnChainCommittees) error
}

// OffChainConfigurable defines methods that allows to
// deploy a local blockchain network for tests and configure CL nodes for Chainlink product.
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
