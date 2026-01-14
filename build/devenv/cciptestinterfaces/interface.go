package cciptestinterfaces

import (
	"context"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
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

// CCIP17 is the main interface for interacting with the CCIP17 protocol.
type CCIP17 interface {
	Chain
	Observable
}

// CCIP17Configuration includes all the interfaces that if implemented allows us to deploy the
// protocol.
// It deploys network-specific infrastructure, configures both CL nodes and contracts and returns
// operations for testing and SLA/Metrics assertions.
type CCIP17Configuration interface {
	OnChainConfigurable
	OffChainConfigurable
}

// Observable pushes Loki streams and exposes Prometheus metrics and returns queries to assert SLAs.
type Observable interface {
	// ExposeMetrics exposes Prometheus metrics for the given source and destination chain IDs.
	ExposeMetrics(ctx context.Context, source, dest uint64) ([]string, *prometheus.Registry, error)
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
	// TokenAmount is an optional field to include a token transfer with the message.
	TokenAmount TokenAmount
	// FeeToken is the fee token to pay in.
	// This is optional - the default means native token is used.
	FeeToken protocol.UnknownAddress
}

// MessageOptions consists of all the ways one can modify a CCIP message
// using extraArgs.
type MessageOptions struct {
	// Version indicates the version of the extraArgs.
	Version uint8
	// ExecutionGasLimit is the execution gas limit for the message
	ExecutionGasLimit uint32
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
	Sender         protocol.UnknownAddress
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
	SourceChainSelector protocol.ChainSelector
	MessageID           [32]byte
	MessageNumber       uint64
	State               MessageExecutionState
	ReturnData          []byte
}

// Chain provides methods to interact with a single chain that has CCIP deployed.
type Chain interface {
	// GetEOAReceiverAddress gets an EOA receiver address for this chain.
	GetEOAReceiverAddress() (protocol.UnknownAddress, error)
	// GetSenderAddress gets the sender address for this chain.
	GetSenderAddress() (protocol.UnknownAddress, error)
	// SendMessage sends a CCIP message to the specified destination chain with the specified message options.
	SendMessage(ctx context.Context, dest uint64, fields MessageFields, opts MessageOptions) (MessageSentEvent, error)
	// SendMessageWithNonce sends a CCIP message to the specified destination chain with the specified message options and nonce.
	SendMessageWithNonce(ctx context.Context, dest uint64, fields MessageFields, opts MessageOptions, sender *bind.TransactOpts, nonce *atomic.Uint64, disableTokenAmountCheck bool) (MessageSentEvent, error)
	// GetUserNonce returns the nonce for the user on this chain.
	GetUserNonce(ctx context.Context) (uint64, error)
	// GetExpectedNextSequenceNumber gets an expected sequence number for message to the specified destination chain.
	GetExpectedNextSequenceNumber(ctx context.Context, to uint64) (uint64, error)
	// WaitOneSentEventBySeqNo waits until exactly one event for CCIP message sent is emitted on-chain for the specified destination chain and sequence number.
	WaitOneSentEventBySeqNo(ctx context.Context, to, seq uint64, timeout time.Duration) (MessageSentEvent, error)
	// WaitOneExecEventBySeqNo waits until exactly one event for CCIP execution state change is emitted on-chain for the specified source chain and sequence number.
	WaitOneExecEventBySeqNo(ctx context.Context, from, seq uint64, timeout time.Duration) (ExecutionStateChangedEvent, error)
	// GetTokenBalance gets the balance of an account for a token on the specified chain.
	GetTokenBalance(ctx context.Context, address, tokenAddress protocol.UnknownAddress) (*big.Int, error)
	// GetMaxDataBytes gets the maximum data size for a CCIP message to the specified remote chain.
	GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error)
	// ManuallyExecuteMessage manually executes a message on this chain and returns an error if the execution fails.
	ManuallyExecuteMessage(ctx context.Context, message protocol.Message, gasLimit uint64, ccvs []protocol.UnknownAddress, verifierResults [][]byte) (ExecutionStateChangedEvent, error)
	// Curse curses a list of chains on this chain.
	Curse(ctx context.Context, subjects [][16]byte) error
	// Uncurse uncurses a list of chains on this chain.
	Uncurse(ctx context.Context, subjects [][16]byte) error
	// GetRoundRobinSendingKey gets the round robin sending key for the chain.
	GetRoundRobinUser() func() *bind.TransactOpts
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
	// FundNodes funds Chainlink nodes for some amount of native/LINK currency
	// using chain-specific clients or CLDF
	FundNodes(ctx context.Context, cls []*nodeset.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error
	// FundAddresses funds addresses for some amount of native currency
	// using chain-specific clients or CLDF
	FundAddresses(ctx context.Context, bc *blockchain.Input, addresses []protocol.UnknownAddress, nativeAmount *big.Int) error
}
