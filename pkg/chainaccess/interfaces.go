package chainaccess

import (
	"context"
	"errors"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// HeadTracker provides access to the latest blockchain head information.
// This interface is responsible for tracking the current and finalized block states.
//
// =================================================================================
// THIS MUST TAKE INTO CONSIDERATION FINALITY TAGS / FINALITY DEPTH.
// =================================================================================
// Reorg detection relies on accurate finalized block info and abstracts away chain-specific details by using this interface.
//
// The recommendation is to use HeadTracker implementations from each chain, e.g. chainlink-evm/pkg/heads.
// Thread-safety: All methods must be safe for concurrent calls.
type HeadTracker interface {
	// LatestAndFinalizedBlock returns the latest and finalized block headers in a single call.
	// This is more efficient than separate RPC calls and provides complete block information
	// including hashes, parent hashes, and timestamps needed for reorg detection.
	LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error)
	// LatestSafeBlock returns the latest block that is considered safe. On Ethereum this is the
	// `safe` head — a checkpoint that is more recent than `finalized` but less final than
	// `finalized`. Returns nil without an error when the chain does not support the safe tag.
	// Mirrors the upstream chainlink-framework chains/heads.Tracker interface.
	LatestSafeBlock(ctx context.Context) (safe *protocol.BlockHeader, err error)
}

// SourceReader defines the interface for reading CCIP message events from source chains.
// This interface abstracts polling-based access to blockchain data and provides
// the foundation for chain-agnostic message reading.
//
// Thread-safety: All methods must be safe for concurrent calls.
type SourceReader interface {
	// FetchMessageSentEvents returns MessageSentEvents in the given block range.
	// A toBlock of 0 queries up to the latest block.
	// Readers return the decoded Message with its receipts and fee asset, and nothing derived
	// from them: a consumer that needs a normalized view builds it at its own boundary. The
	// Message is what signing and message IDs are computed over and must be returned unchanged.
	FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock uint64) ([]protocol.MessageSentEvent, error)

	// GetBlocksHeaders returns the full block headers for a batch of block numbers.
	// This is more efficient than individual calls when building the chain tail.
	// If a block is not found or RPC call fails for a specific block, it will be omitted from the result.
	// Callers should check if all requested blocks are present in the returned map.
	GetBlocksHeaders(ctx context.Context, blockNumbers []uint64) (map[uint64]protocol.BlockHeader, error)

	// HeadTracker Embed HeadTracker for blockchain head tracking functionality.
	HeadTracker

	// RMNCurseReader Embed RMNCurseReader for curse detection functionality.
	RMNCurseReader
}

// CriticalSourceInvariantCallbackSetter is an optional SourceReader capability for attaching the
// verifier's critical-invariant metric callback. Callers must set it before the reader starts.
type CriticalSourceInvariantCallbackSetter interface {
	// SetCriticalSourceInvariantCallback attaches the callback invoked when a critical source-chain
	// invariant is violated. It must be called before the reader starts.
	SetCriticalSourceInvariantCallback(callback func(context.Context))
}

// FinalityViolationReporter is a chain's own finality-violation signal, such as the EVM log poller's.
// The verifier is handed one per chain that has it and uses it instead of comparing block headers.
type FinalityViolationReporter interface {
	// FinalityViolated reports whether the data source currently detects a finality violation.
	FinalityViolated() bool
}

// SourceHealthReporter is an optional SourceReader capability for a chain's own health signal, such as the
// EVM log poller's. Finality violations are not part of it: they are reported only through FinalityViolationReporter.
type SourceHealthReporter interface {
	// Healthy returns nil when the data source is healthy, otherwise the reason it is not.
	Healthy() error
}

// ErrSourceNotReady is returned by SourceReader reads while the source is still loading; callers retry
// later and must not treat the range as scanned.
var ErrSourceNotReady = errors.New("source not ready")

// ErrSourceReaderDisabled is returned by SourceReader reads after a critical source-chain invariant
// violation permanently disabled the reader; the chain stays down until an operator intervenes.
var ErrSourceReaderDisabled = errors.New("source reader disabled after critical invariant violation")

// SourceLoader is an optional SourceReader capability for readers that must load a local index, such as
// the EVM log poller, before serving reads.
type SourceLoader interface {
	// LoadFrom starts loading from startBlock without blocking; reads return ErrSourceNotReady until done.
	LoadFrom(startBlock uint64)
	// Loaded returns nil once loading has finished and an error wrapping ErrSourceNotReady until then, which
	// the verifier reports in its health.
	Loaded() error
	// Close stops loading and releases what LoadFrom set up. Only SourceLoaders are closed by the verifier.
	Close() error
}

// ExecutorMonitoringSetter is an optional capability of accessor-provided destination readers and
// contract transmitters. Accessor factories build these components before the executor's
// process-level monitoring exists, so they hold a no-op implementation; the executor attaches the
// real one through this hook before the coordinator starts. It must be called before the component
// starts serving calls.
type ExecutorMonitoringSetter interface {
	// SetExecutorMonitoring replaces the component's monitoring with the executor's process-level
	// implementation.
	SetExecutorMonitoring(monitoring.Monitoring)
}

// RMNCurseReader provides read-only access to RMN Remote curse state.
// Both SourceReader and DestinationReader implement this interface.
type RMNCurseReader interface {
	// GetRMNCursedSubjects queries the configured RMN Remote contract.
	// Returns cursed subjects as bytes16, which can be:
	// - Global curse constant (0x0100000000000000000000000000000001)
	// - Chain selectors as bytes16s
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
}

// MessageFilter defines an interface for filtering protocol.MessageSentEvent.
type MessageFilter interface {
	// Filter returns true if the given MessageSentEvent should be processed, false to skip it.
	Filter(msg protocol.MessageSentEvent) bool
}

// CCTPCodec holds the chain-specific CCTP knowledge the token verifier needs: the Circle
// domain of a source chain, and the codecs for that chain's native transaction hash and
// address encodings.
//
// A chain family implements CCTPCodec on its chain accessor, so the accessor resolved for
// a source chain is also the codec for that chain. The verifier reads the codecs it was
// given and never branches on a chain family.
type CCTPCodec interface {
	// Domain returns the Circle CCTP domain for the source chain selector.
	Domain(selector protocol.ChainSelector) (uint32, bool)
	// EncodeTxHash renders a source transaction hash in the format Circle's API expects.
	EncodeTxHash(txHash protocol.ByteSlice) string
	// DecodeAddress parses an address Circle returned for the source chain.
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}

// FeeQuoterReader reads a chain's Fee Quoter contract.
//
// Thread-safety: All methods must be safe for concurrent calls.
type FeeQuoterReader interface {
	// GetFQState reads the Fee Quoter's current on-chain state.
	GetFQState(ctx context.Context) (protocol.FQState, error)
}

// FeeQuoterWriter updates the prices stored in a chain's Fee Quoter contract.
//
// Thread-safety: All methods must be safe for concurrent calls.
type FeeQuoterWriter interface {
	// UpdatePrices generates and broadcasts a transaction for the given fee token
	// and gas token price updates to the chain.
	UpdatePrices(ctx context.Context, tokenPrices []protocol.FeeTokenPriceUpdate, gasPrices []protocol.GasTokenPriceUpdate) error
}

// GasPriceReader reads a chain's current native gas price from the RPC.
//
// Thread-safety: All methods must be safe for concurrent calls.
type GasPriceReader interface {
	// GetGasPrice reads the chain's current native gas price.
	GetGasPrice(ctx context.Context) (protocol.NativeGasPrice, error)
}

// Accessor provides objects that in turn provide specific kinds of blockchain access.
// It is scoped to a particular chain selector. All methods are optional: implementations
// return an error for capabilities they do not support.
//
// A committee/verifier accessor typically provides only SourceReader.
// An executor accessor typically provides only DestinationReader and ContractTransmitter.
// A price reporting accessor typically provides FeeQuoterReader, FeeQuoterWriter, and GasPriceReader.
type Accessor interface {
	// SourceReader returns the SourceReader for this chain, or an error if not available.
	SourceReader() (SourceReader, error)
	// DestinationReader returns the DestinationReader for this chain, or an error if not available.
	DestinationReader() (DestinationReader, error)
	// ContractTransmitter returns the ContractTransmitter for this chain, or an error if not available.
	ContractTransmitter() (ContractTransmitter, error)
	// CCTPCodec returns the CCTPCodec for this chain, or an error if not available.
	CCTPCodec() (CCTPCodec, error)
	// FeeQuoterReader returns the FeeQuoterReader for this chain, or an error if not available.
	FeeQuoterReader() (FeeQuoterReader, error)
	// FeeQuoterWriter returns the FeeQuoterWriter for this chain, or an error if not available.
	FeeQuoterWriter() (FeeQuoterWriter, error)
	// GasPriceReader returns the GasPriceReader for this chain, or an error if not available.
	GasPriceReader() (GasPriceReader, error)
	// Close releases any background services the accessor started. Stateless accessors return nil.
	Close() error

	// Optional hook: health.DegradedReporter
	//
	// Accessors that keep working with a missing part (for example, a missing signing key)
	// should implement Degraded() error. The service that owns the accessor reports it on /health.

	// Optional hook: bootstrap.KeystoreSetter
	//
	// Accessors that require a keystore for signing (e.g. to build a keystore-backed
	// ContractTransmitter) should also implement bootstrap.KeystoreSetter:
	//
	//   SetKeystore(ctx context.Context, ks keystore.Keystore) error
	//
	// bootstrap.KeystoreRegistry checks for this interface after every GetAccessor call
	// and invokes SetKeystore automatically, so implementations do not need to arrange
	// injection themselves.
}

// AccessorFactory creates Accessors for specific chain selectors.
type AccessorFactory interface {
	// GetAccessor returns the Accessor for the given chain selector.
	GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error)
}

// DestinationReader is an interface for reading message status and data from a single destination chain.
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain.
type DestinationReader interface {
	// RMNCurseReader Embed RMNCurseReader for curse detection functionality. This can point to the same implementation as the SourceReader.
	RMNCurseReader
	// GetMessageSuccess returns true if message has on-chain success state.
	GetMessageSuccess(ctx context.Context, message protocol.Message) (bool, error)
	// GetCCVSForMessage return cross-chain verifications for selected message
	GetCCVSForMessage(ctx context.Context, message protocol.Message) (protocol.CCVAddressInfo, error)
	// GetExecutionAttempts returns the full list of execution attempts for a given message within the executable window.
	GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]protocol.ExecutionAttempt, error)
	// AttemptChecker Embed AttemptChecker for execution attempt validation functionality.
	AttemptChecker
}

// ContractTransmitter is an interface for transmitting messages to destination chains that should be implemented by chain-specific transmitters.
type ContractTransmitter interface {
	// ConvertAndWriteMessageToChain takes an aggregated report and transmits it in the format expected by the destination chain.
	ConvertAndWriteMessageToChain(ctx context.Context, report protocol.AbstractAggregatedReport) error
}

// AttemptChecker validates execution attempts and reports readiness and health
// for a destination chain's execution attempt poller.
type AttemptChecker interface {
	// IsReady reports whether the destination reader for the given chain has
	// completed its startup and is ready to serve execution attempt data.
	// A false return indicates a transient condition (e.g. backfill in progress)
	// that will resolve on its own; callers should retry later.
	IsReady(chain protocol.ChainSelector) bool
	// CheckHealth returns nil when the destination reader is operating normally.
	// A non-nil error indicates an unrecoverable failure (e.g. the execution
	// attempt poller could not determine its start block). Messages destined
	// for an unhealthy chain should be rejected, not retried.
	CheckHealth(chain protocol.ChainSelector) error
	// HasHonestAttempt reports whether an honest execution attempt has been
	// made for the given message. If it has not, the result tells if an attempt
	// that is not honest exists.
	HasHonestAttempt(ctx context.Context, message protocol.Message, verifierResults []protocol.VerifierResult, ccvAddressInfo protocol.CCVAddressInfo) (HonestAttemptCheck, error)
}

// HonestAttemptCheck is the result of DestinationReader.HasHonestAttempt.
type HonestAttemptCheck struct {
	// Honest is true if an honest execution attempt exists.
	Honest bool
	// NotHonestAttemptExists is true if an attempt exists and none of the attempts is honest.
	NotHonestAttemptExists bool
}
