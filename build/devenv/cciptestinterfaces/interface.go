package cciptestinterfaces

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"
	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	tokensapi "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
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

// ErrInsufficientNativeBalance is returned by TransferNative when the from account does not hold
// enough native balance to cover the gas cost of the transfer. Callers can use errors.Is to
// distinguish this case from other transfer failures (e.g. to skip rather than abort).
var ErrInsufficientNativeBalance = errors.New("insufficient native balance to cover gas cost")

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

// MessageSentEvent is a chain-agnostic representation of the output of a ccipSend operation.
type MessageSentEvent struct {
	MessageID      protocol.Bytes32
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

func (m MessageExecutionState) String() string {
	switch m {
	case ExecutionStateUntouched:
		return "UNTOUCHED"
	case ExecutionStateInProgress:
		return "IN_PROGRESS"
	case ExecutionStateSuccess:
		return "SUCCESS"
	case ExecutionStateFailure:
		return "FAILURE"
	default:
		return fmt.Sprintf("unknown execution state %d", m)
	}
}

// ExecutionStateChangedEvent is a chain-agnostic representation of the output of a ccip message execution operation.
type ExecutionStateChangedEvent struct {
	SourceChainSelector protocol.ChainSelector
	MessageID           [32]byte
	MessageNumber       uint64
	State               MessageExecutionState
	ReturnData          []byte
}

// MessageEventKey identifies a CCIP message event by sequence number or message ID.
// User should only define one or the other.
type MessageEventKey struct {
	SeqNum    uint64
	MessageID protocol.Bytes32
}

// Chain provides methods to interact with a single chain that has CCIP deployed.
type Chain interface {
	// GetEOAReceiverAddress gets an EOA receiver address for this chain.
	GetEOAReceiverAddress() (protocol.UnknownAddress, error)
	// GetSenderAddress gets the sender address for this chain.
	GetSenderAddress() (protocol.UnknownAddress, error)
	// SendMessage sends a CCIP message to the specified destination chain with the specified message options.
	SendMessage(ctx context.Context, dest uint64, fields MessageFields, dataProvider ExtraArgsDataProvider) (MessageSentEvent, error)
	// GetExpectedNextSequenceNumber gets an expected sequence number for message to the specified destination chain.
	GetExpectedNextSequenceNumber(ctx context.Context, to uint64) (uint64, error)
	// ConfirmSendOnSource waits until exactly one CCIPMessageSent event is emitted on-chain for the specified destination chain, identified by sequence number or message ID.
	ConfirmSendOnSource(ctx context.Context, to uint64, key MessageEventKey, timeout time.Duration) (MessageSentEvent, error)
	// ConfirmExecOnDest waits until exactly one ExecutionStateChanged event is emitted on-chain for the specified source chain, identified by sequence number or message ID.
	ConfirmExecOnDest(ctx context.Context, from uint64, key MessageEventKey, timeout time.Duration) (ExecutionStateChangedEvent, error)
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
	// ChainSelector gets the selector for this chain.
	ChainSelector() uint64
	// NativeBalance returns the native token balance of the given address on this chain.
	NativeBalance(ctx context.Context, address protocol.UnknownAddress) (*big.Int, error)
	// TransferNative sends native tokens from a configured account to any destination address.
	// The from address must match one of the accounts provisioned in the environment (the deployer
	// key or one of the user keys); if it does not, an error is returned.
	// When amount is nil the full spendable balance (balance minus estimated gas cost) is swept.
	TransferNative(ctx context.Context, from, to protocol.UnknownAddress, amount *big.Int) error
}

// LombardMailboxBridgedMessageSetter is optionally implemented by chain implementations (e.g. EVM)
// that can set the Lombard mock mailbox's bridged message (verifier version + message ID) on the
// destination chain so deliverAndHandle returns exactly 36 bytes and LombardVerifier.verifyMessage succeeds.
type LombardMailboxBridgedMessageSetter interface {
	SetLombardMailboxBridgedMessage(ctx context.Context, messageID [32]byte) error
}

// ProgressableChain is optionally implemented by chain families that can
// drive block progression on demand (e.g. anvil via evm_mine). Test code
// must type-assert and also call SupportManualBlockProgress at runtime,
// since the static interface only proves the methods exist - the
// underlying node (e.g. a real testnet RPC) may still reject them.
type ProgressableChain interface {
	// SupportManualBlockProgress returns true iff the underlying node both
	// supports forced block progression AND is configured to mine on each
	// tx (so messages sent by tests actually get included).
	SupportManualBlockProgress(ctx context.Context) bool
	// AdvanceBlocks mines numBlocks blocks on the chain.
	AdvanceBlocks(ctx context.Context, numBlocks int) error
}

// SnapshotID identifies a snapshot taken on a ReorgableChain. It is
// opaque to the caller; each chain family defines its own encoding.
type SnapshotID []byte

// ReorgableChain is optionally implemented by chain families that can
// snapshot and revert the node state to simulate reorgs (e.g. anvil via
// evm_snapshot / evm_revert). Keep this distinct from ProgressableChain:
// a curse test only needs block progression, not reorg primitives.
type ReorgableChain interface {
	// SupportReorgs returns true iff the underlying node supports taking
	// snapshots and reverting to them.
	SupportReorgs(ctx context.Context) bool
	// Snapshot captures the current chain state and returns an ID that
	// can be passed to Revert.
	Snapshot(ctx context.Context) (SnapshotID, error)
	// Revert restores the chain to the state captured by the given
	// snapshot. Implementations may invalidate the snapshot after a
	// successful revert - check the implementation before reusing an ID.
	Revert(ctx context.Context, id SnapshotID) error
}

type OnChainCommittees struct {
	CommitteeQualifier string
	Signers            [][]byte
	Threshold          uint8
}

// ChainLaneProfile holds everything an impl needs to provide so that
// connectAllChains can assemble PartialChainConfig entries for the
// canonical ConfigureChainsForLanesFromTopology changeset.
// Contract addresses (Router, OnRamp, FeeQuoter, OffRamp, Executor) are
// resolved from the datastore by the changeset itself.
//
// Fields use the changeset's override/pointer types directly so family impls
// express only the values they want to override; nil/zero means "use adapter default".
type ChainLaneProfile struct {
	BaseExecutionGasCost     *uint32
	FeeQuoterDestChainConfig ccipChangesets.FeeQuoterDestChainConfigOverrides
	ExecutorDestChainConfig  *adapters.ExecutorDestChainConfig
	DefaultExecutorQualifier string
	DefaultInboundCCVs       []datastore.AddressRef
	DefaultOutboundCCVs      []datastore.AddressRef
	TokenReceiverAllowed     *bool
	GasForVerification       *uint32
	AllowedFinalityConfig    *finality.Config
}

// TokenConfigProvider abstracts the chain-specific decisions that feed into
// TokenExpansion (token type, decimals, admin addresses, pre-mint amounts)
// and any post-deployment work (e.g. funding lock-release pools on EVM).
//
// It is separate from OnChainConfigurable so chain families can deploy CCIP
// core contracts and lanes without implementing token pools (e.g. messaging-only
// or AltVM before token support exists). Devenv uses type assertions; when absent,
// token deployment and ConfigureTokensForTransfers are skipped.
type TokenConfigProvider interface {
	// GetSupportedPools returns pool types and versions this chain can deploy.
	GetSupportedPools() []devenvcommon.PoolCapability

	// GetTokenExpansionConfigs returns one TokenExpansionInputPerChain per
	// token/pool that should be deployed on the given chain, driven by the
	// pre-computed token combinations. Return nil, nil if token transfers
	// are not supported.
	GetTokenExpansionConfigs(
		env *deployment.Environment,
		selector uint64,
		combos []devenvcommon.TokenCombination,
	) ([]tokensapi.TokenExpansionInputPerChain, error)

	// PostTokenDeploy runs chain-specific work after all tokens and pools have
	// been deployed via TokenExpansion (e.g. funding lock-release pools on EVM).
	PostTokenDeploy(
		env *deployment.Environment,
		selector uint64,
		deployedRefs []datastore.AddressRef,
	) error

	// GetTokenTransferConfigs builds TokenTransferConfig entries for all pools
	// deployed on this chain, using chain-specific registry and CCV refs.
	GetTokenTransferConfigs(
		env *deployment.Environment,
		selector uint64,
		remoteSelectors []uint64,
		topology *offchain.EnvironmentTopology,
	) ([]tokensapi.TokenTransferConfig, error)
}

// OnChainConfigurable defines methods that allows devenv to
// deploy, configure Chainlink product and connect on-chain part with other chains.
//
// Contract deployment follows the 1.6 pattern: a shared common function calls
// the tooling API DeployChainContracts changeset. Chain impls provide only
// configuration (GetDeployChainContractsCfg) and optional pre/post hooks.
type OnChainConfigurable interface {
	// ChainFamily returns the family of the chain.
	ChainFamily() string
	// PreDeployContractsForSelector runs chain-specific setup before the common
	// DeployChainContracts call (e.g. deploying CREATE2 factory on EVM).
	// The returned DataStore is merged into env.DataStore before
	// GetDeployChainContractsCfg is called.
	PreDeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, topology *offchain.EnvironmentTopology) (datastore.DataStore, error)
	// GetDeployChainContractsCfg returns the per-chain configuration for the
	// common DeployChainContracts changeset. Called after Pre, so env.DataStore
	// includes pre-deployed addresses (e.g. CREATE2 factory).
	GetDeployChainContractsCfg(env *deployment.Environment, selector uint64, topology *offchain.EnvironmentTopology) (ccipChangesets.DeployChainContractsPerChainCfg, error)
	// PostDeployContractsForSelector runs chain-specific setup after the common
	// DeployChainContracts call (e.g. deploying USDC/Lombard token pools on EVM).
	// The returned DataStore is merged into the final result.
	PostDeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, topology *offchain.EnvironmentTopology) (datastore.DataStore, error)
	// GetConnectionProfile returns a ChainDefinition describing this chain as a
	// lane destination, plus the default committee verifier config to apply for
	// each remote chain. The environment uses profiles from all chains to
	// assemble the full cross-chain connection config.
	GetConnectionProfile(env *deployment.Environment, selector uint64) (lanes.ChainDefinition, lanes.CommitteeVerifierRemoteChainInput, error)
	// GetChainLaneProfile returns the lane profile for this chain, containing
	// local contract refs, destination characteristics, and default per-remote
	// settings. The environment uses profiles from all chains to assemble the
	// full cross-chain connection config.
	GetChainLaneProfile(env *deployment.Environment, selector uint64) (ChainLaneProfile, error)
	// PostConnect runs chain-specific setup after all chains have been connected
	// (e.g. USDC/Lombard token config, custom executor wiring).
	PostConnect(env *deployment.Environment, selector uint64, remoteSelectors []uint64) error
}

// ExtraArgsSerializer serializes message extra args for a destination chain family.
// Product repos register their implementation via RegisterExtraArgsSerializer.
type ExtraArgsSerializer func(provider ExtraArgsDataProvider) ([]byte, error)

var (
	extraArgsSerializers   = make(map[string]ExtraArgsSerializer)
	extraArgsSerializersMu sync.RWMutex
)

// RegisterExtraArgsSerializer registers an ExtraArgsSerializer for a chain family.
// If the family is already registered, the call is a no-op to match the pattern
// used by other registries in this repo (e.g. CLDFProviderRegistry, ImplFactory).
// Product repos call this in their init() alongside other registrations.
func RegisterExtraArgsSerializer(family string, serializer ExtraArgsSerializer) {
	extraArgsSerializersMu.Lock()
	defer extraArgsSerializersMu.Unlock()
	if _, ok := extraArgsSerializers[family]; ok {
		return
	}
	extraArgsSerializers[family] = serializer
}

// GetExtraArgsSerializer returns the registered serializer for the given chain family.
func GetExtraArgsSerializer(family string) (ExtraArgsSerializer, bool) {
	extraArgsSerializersMu.RLock()
	defer extraArgsSerializersMu.RUnlock()
	s, ok := extraArgsSerializers[family]
	return s, ok
}

// DeployerNonceBumper is an optional interface. When implemented, devenv calls it before
// DeployContractsForSelector so that contract addresses differ across chains (e.g. by sending
// dummy self-transfers to bump the deployer nonce). This helps smoke tests catch bugs where
// code looks up addresses using the wrong chain selector.
type DeployerNonceBumper interface {
	BumpDeployerNonce(ctx context.Context, env *deployment.Environment, selector uint64, count int) error
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

// ChainSendOption is a marker interface for chain-specific send parameters.
// The expected usage is that a chain family integration will define a struct that satisfies this interface, then type check against their struct in their test.
// Generic tests accept `ChainSendOption` as a parameter, the implementation casts the parameter to their struct type and uses it.
type ChainSendOption interface {
	IsSendOption() bool
}

// ExtraArgsDataProvider is a marker interface for destination-shaped extra-args data.
// A source chain's BuildChainMessage type-switches on the concrete provider to pick
// the right encoder. Each chain family defines its own concrete provider struct.
type ExtraArgsDataProvider interface {
	IsExtraArgsDataProvider()
}

type genericChain interface {
	ChainSelector() uint64
}

// ChainAsDestination is implemented by any chain that can RECEIVE CCIP messages.
// Chain families can implement this interface to run partial CCIP message tests without having to implement the full `Chain` interface.
type ChainAsDestination interface {
	genericChain
	// ExtraArgsProvider returns the extra-args data provider for this destination chain.
	// The output of this method will be passed to the ExtraArgsEncoder in ChainAsSource.
	// ExtraArgsProvider(any) (ExtraArgsDataProvider, error)
	// GetEOAReceiverAddress returns an EOA receiver address for this chain.
	GetEOAReceiverAddress() (protocol.UnknownAddress, error)
	// ConfirmExecOnDest confirms that a CCIP message was executed on this chain.
	// Implementation should support confirmation by either message ID or sequence number, passed in as the `MessageEventKey`.
	// The timeout is the maximum duration to wait for the event to be emitted.
	ConfirmExecOnDest(ctx context.Context, from uint64, key MessageEventKey, timeout time.Duration) (ExecutionStateChangedEvent, error)
}

// ChainAsSource is implemented by any chain that can ORIGINATE CCIP messages.
// Chain families can implement this interface to run partial CCIP message tests without having to implement the full `Chain` interface.
type ChainAsSource interface {
	genericChain
	// ExtraArgsSerializer serializes the extra args for the given destination chain.
	// Implementation should type assert the ExtraArgsDataProvider to struct types from supported destination chain families.
	ExtraArgsSerializer(ExtraArgsDataProvider) ([]byte, error)
	// BuildChainMessage builds a CCIP message for the given destination chain.
	// It will call into the registered extra args serializer per destination chain for now, until we have a more generic way to manage extra args.
	// It returns a generic type that is specific to the chain family. The returned message is expected to be directly passed in ot the SendChainMessage method.
	// For example, the EVM implementation returns a routerwrapper.ClientEVM2AnyMessage.
	BuildChainMessage(ctx context.Context, destChain uint64, messageFields MessageFields, extraArgs []byte) (GenericChainMessage, error)
	// SendChainMessage sends a CCIP message to the given destination chain.
	// sendOptions is a Marker Interface for chain-specific send parameters. Expected usage is that implementation will type assert the sendOption to their struct type and use it.
	// For example, the EVM implementation will type assert the sendOption to evm.EVMSendOptions to access nonce/sender/etc.
	// The ChainAsSourceMessage is expected to be the same type that was returned by the BuildChainMessage method. For EVM this is routerwrapper.ClientEVM2AnyMessage.
	SendChainMessage(ctx context.Context, destChain uint64, message GenericChainMessage, sendOption ChainSendOption) (MessageSentEvent, protocol.ByteSlice, error)
	// ConfirmSendOnSource confirms that a CCIP message was sent on this chain.
	// Implementation should support confirmation by either message ID or sequence number, passed in as the `MessageEventKey`.
	// The timeout is the maximum duration to wait for the event to be emitted.
	ConfirmSendOnSource(ctx context.Context, to uint64, key MessageEventKey, timeout time.Duration) (MessageSentEvent, error)
}

// GenericChainMessage is a generic type to indicate to users that the message generated from BuildChainMessage is expected to be passed directly to SendChainMessage.
// For example, EVM will return a routerwrapper.ClientEVM2AnyMessage.
type GenericChainMessage any
