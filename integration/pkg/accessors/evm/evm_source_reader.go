package evm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/rmnremotereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Compile-time checks to ensure SourceReader implements the SourceReader interface.
var (
	_ chainaccess.SourceReader                          = (*SourceReader)(nil)
	_ chainaccess.CriticalSourceInvariantCallbackSetter = (*SourceReader)(nil)
)

// SourceReaderParams are the dependencies shared by the RPC and log poller source readers.
type SourceReaderParams struct {
	ChainClient   client.Client
	HeadTracker   heads.Tracker
	OnRampAddress common.Address
	// ConfiguredRMNRemoteAddress is DEPRECATED, zero when unset: the RMN Remote address is derived from
	// the OnRamp's static config. When set and it disagrees, a warning is logged and the derived one used.
	ConfiguredRMNRemoteAddress common.Address
	CCIPMessageSentTopic       string
	ChainSelector              protocol.ChainSelector
	Logger                     logger.Logger
	HeaderFetchBatchSize       int
	OnCriticalInvariant        func(context.Context)
}

// sourceReaderCore is what both source readers share: block headers, head tracker reads, RMN curse
// reads and CCIPMessageSent decoding. Each reader adds its own log source on top.
type sourceReaderCore struct {
	chainClient   client.Client
	headTracker   heads.Tracker
	onRampAddress common.Address
	// configuredRMNRemoteAddress is the deprecated configured address, zero when unset. The
	// authoritative address is derived lazily from the OnRamp's static config at query time.
	configuredRMNRemoteAddress       common.Address
	rmnRemoteCaller                  *lazy.Lazy[rmn_remote.RMNRemoteCaller]
	ccipMessageSentTopic             string
	chainSelector                    protocol.ChainSelector
	lggr                             logger.Logger
	onRampABI                        *abi.ABI // Cached ABI to avoid re-parsing
	onCriticalInvariant              func(context.Context)
	sourceReaderHeaderFetchBatchSize int
}

// SourceReader reads CCIPMessageSent logs over RPC with eth_getLogs.
type SourceReader struct {
	sourceReaderCore
}

func NewEVMSourceReader(ctx context.Context, p SourceReaderParams) (chainaccess.SourceReader, error) {
	core, err := newSourceReaderCore(p)
	if err != nil {
		return nil, err
	}
	return &SourceReader{sourceReaderCore: core}, nil
}

func newSourceReaderCore(p SourceReaderParams) (sourceReaderCore, error) {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(p.ChainClient, "chainClient")
	appendIfNil(p.HeadTracker, "headTracker")
	appendIfNil(p.Logger, "logger")

	if p.OnRampAddress == (common.Address{}) {
		errs = append(errs, fmt.Errorf("onRampAddress is not set"))
	}
	if p.CCIPMessageSentTopic == "" {
		errs = append(errs, fmt.Errorf("ccipMessageSentTopic is not set"))
	}
	if p.ChainSelector == 0 {
		errs = append(errs, fmt.Errorf("chainSelector is not set"))
	}

	if len(errs) > 0 {
		return sourceReaderCore{}, errors.Join(errs...)
	}

	// Bind to the OnRamp contract to derive the RMN Remote address from its static config.
	// Binding only parses the ABI and issues no RPC; the authoritative RMN Remote address is
	// read lazily on first GetRMNCursedSubjects so construction never fails on an RPC error.
	onRampCaller, err := onramp.NewOnRampCaller(p.OnRampAddress, p.ChainClient)
	if err != nil {
		return sourceReaderCore{}, fmt.Errorf("failed to bind OnRamp contract at %s: %w",
			p.OnRampAddress.Hex(), err)
	}

	lggr := p.Logger
	// Derive + bind the RMN Remote caller on first use, then cache it. A transient failure is
	// not cached, so a rate-limited or otherwise unavailable RPC retries on the next call.
	rmnRemoteCaller := lazy.New(func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error) {
		// One-shot read of an immutable value, so a short timeout suffices.
		deriveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		rmnRemoteAddress, err := deriveRMNRemoteFromOnRamp(deriveCtx, onRampCaller)
		if err != nil {
			return rmn_remote.RMNRemoteCaller{}, err
		}
		lggr.Infow("Derived RMN Remote address from OnRamp static config",
			"chainSelector", p.ChainSelector,
			"rmnRemoteAddress", rmnRemoteAddress.Hex())
		if p.ConfiguredRMNRemoteAddress != (common.Address{}) && p.ConfiguredRMNRemoteAddress != rmnRemoteAddress {
			lggr.Warnw("Configured RMN Remote address does not match the OnRamp static config; using the derived address",
				"chainSelector", p.ChainSelector,
				"configuredRmnRemoteAddress", p.ConfiguredRMNRemoteAddress.Hex(),
				"rmnRemoteAddress", rmnRemoteAddress.Hex())
		}
		caller, err := rmn_remote.NewRMNRemoteCaller(rmnRemoteAddress, p.ChainClient)
		if err != nil {
			return rmn_remote.RMNRemoteCaller{}, fmt.Errorf("failed to bind RMN Remote contract at %s: %w",
				rmnRemoteAddress.Hex(), err)
		}
		return *caller, nil
	})

	// Get and cache the OnRamp ABI once during initialization
	onRampABI, err := onramp.OnRampMetaData.GetAbi()
	if err != nil {
		return sourceReaderCore{}, fmt.Errorf("failed to get OnRamp ABI: %w", err)
	}

	core := sourceReaderCore{
		chainClient:                      p.ChainClient,
		headTracker:                      p.HeadTracker,
		onRampAddress:                    p.OnRampAddress,
		configuredRMNRemoteAddress:       p.ConfiguredRMNRemoteAddress,
		rmnRemoteCaller:                  rmnRemoteCaller,
		ccipMessageSentTopic:             p.CCIPMessageSentTopic,
		chainSelector:                    p.ChainSelector,
		lggr:                             lggr,
		onRampABI:                        onRampABI,
		sourceReaderHeaderFetchBatchSize: sourceReaderHeaderFetchBatchSize(p.HeaderFetchBatchSize),
	}
	core.SetCriticalSourceInvariantCallback(p.OnCriticalInvariant)
	return core, nil
}

// onRampStaticConfigGetter is the slice of the OnRamp binding the source reader needs, defined
// as an interface so the RMN derivation is unit-testable.
type onRampStaticConfigGetter interface {
	GetStaticConfig(opts *bind.CallOpts) (onramp.OnRampStaticConfig, error)
}

// deriveRMNRemoteFromOnRamp reads the chain's RMN Remote address from the OnRamp's
// constructor-set static config. The on-chain value is authoritative: it is the RMN the OnRamp
// itself enforces, so it cannot drift from a stale or mistyped configured address.
func deriveRMNRemoteFromOnRamp(ctx context.Context, onRamp onRampStaticConfigGetter) (common.Address, error) {
	cfg, err := onRamp.GetStaticConfig(&bind.CallOpts{Context: ctx})
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to read OnRamp static config: %w", err)
	}
	if cfg.RmnRemote == (common.Address{}) {
		return common.Address{}, errors.New("OnRamp static config has a zero RMN Remote address")
	}
	return cfg.RmnRemote, nil
}

// SetCriticalSourceInvariantCallback attaches the metric callback invoked when source-chain data
// violates a configured on-chain invariant. It must be called before the reader starts.
func (r *sourceReaderCore) SetCriticalSourceInvariantCallback(callback func(context.Context)) {
	if callback == nil {
		callback = func(context.Context) {}
	}
	r.onCriticalInvariant = callback
}

// GetBlocksHeaders fetches headers for the given block numbers and returns them
// keyed by block number. Requests are batched into a single eth_getBlockByNumber
// batch per chunk (instead of one RPC request per block) to reduce RPC load.
// Batches are chunked to avoid an oversized single payload.
// Zero is a valid height (genesis) and is fetched literally: unlike the former
// []*big.Int input there is no nil element that silently resolves to "latest".
func (r *sourceReaderCore) GetBlocksHeaders(ctx context.Context, blockNumbers []uint64) (map[uint64]protocol.BlockHeader, error) {
	headers := make(map[uint64]protocol.BlockHeader, len(blockNumbers))
	batchSize := sourceReaderHeaderFetchBatchSize(r.sourceReaderHeaderFetchBatchSize)
	for bn := 0; bn < len(blockNumbers); bn += batchSize {
		end := min(bn+batchSize, len(blockNumbers))
		chunk, err := r.fetchHeadBatch(ctx, blockNumbers[bn:end])
		if err != nil {
			r.lggr.Warnw("Failed to fetch header batch", "error", err, "batchStart", bn, "batchEnd", end)
			continue
		}
		maps.Copy(headers, chunk)
	}
	return headers, nil
}

// fetchHeadBatch issues a single batched eth_getBlockByNumber for blockNumbers
// and returns the resulting headers keyed by block number. Individual batch
// element failures are logged and skipped so a single bad block does not discard
// the whole batch.
func (r *sourceReaderCore) fetchHeadBatch(ctx context.Context, blockNumbers []uint64) (map[uint64]protocol.BlockHeader, error) {
	batch := make([]rpc.BatchElem, len(blockNumbers))
	for i, n := range blockNumbers {
		var head *evmtypes.Head
		batch[i] = rpc.BatchElem{
			Method: "eth_getBlockByNumber",
			Args:   []any{client.ToBlockNumArg(new(big.Int).SetUint64(n)), false},
			Result: &head,
		}
	}

	if err := r.chainClient.BatchCallContext(ctx, batch); err != nil {
		return nil, err
	}

	headers := make(map[uint64]protocol.BlockHeader, len(blockNumbers))
	for i, n := range blockNumbers {
		if batch[i].Error != nil {
			r.lggr.Warnw("Failed to get block header", "blockNumber", n, "error", batch[i].Error)
			continue
		}
		headPtr, ok := batch[i].Result.(**evmtypes.Head)
		if !ok || headPtr == nil || *headPtr == nil {
			r.lggr.Warnw("Nil block header", "blockNumber", n)
			continue
		}
		head := *headPtr
		if head.Number < 0 {
			return nil, fmt.Errorf("block number cannot be negative: %d", head.Number)
		}
		blockNum := uint64(head.Number)
		headers[blockNum] = protocol.BlockHeader{
			Number:     blockNum,
			Hash:       protocol.Bytes32(head.Hash),
			ParentHash: protocol.Bytes32(head.ParentHash),
			Timestamp:  head.Timestamp,
		}
	}
	return headers, nil
}

// FetchMessageSentEvents returns MessageSentEvents in the given block range.
// A toBlock of 0 queries up to the latest block.
func (r *SourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock uint64) ([]protocol.MessageSentEvent, error) {
	logs, err := r.rpcLogs(ctx, fromBlock, toBlock)
	if err != nil {
		return nil, err
	}
	return r.parseMessageSentLogs(ctx, logs), nil
}

// rpcLogs reads CCIPMessageSent logs in the given block range with eth_getLogs.
func (r *SourceReader) rpcLogs(ctx context.Context, fromBlock, toBlock uint64) ([]types.Log, error) {
	// ethereum.FilterQuery uses nil for an open-ended upper bound; the interface's 0 maps to it.
	var toBlockArg *big.Int
	if toBlock != 0 {
		toBlockArg = new(big.Int).SetUint64(toBlock)
	}
	rangeQuery := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(fromBlock),
		ToBlock:   toBlockArg,
		Addresses: []common.Address{r.onRampAddress},
		Topics:    [][]common.Hash{{common.HexToHash(r.ccipMessageSentTopic)}},
	}
	logs, err := r.chainClient.FilterLogs(ctx, rangeQuery)
	if err != nil {
		r.lggr.Warnw("Failed to filter logs", "error", err)
		return nil, err
	}
	return logs, nil
}

// parseMessageSentLogs decodes and validates CCIPMessageSent logs. Invalid logs are reported
// through onCriticalInvariant and skipped.
func (r *sourceReaderCore) parseMessageSentLogs(ctx context.Context, logs []types.Log) []protocol.MessageSentEvent {
	results := make([]protocol.MessageSentEvent, 0, len(logs))

	// Process found events
	for _, log := range logs {
		r.lggr.Debugw("Found CCIPMessageSent event",
			"chainSelector", r.chainSelector,
			"blockNumber", log.BlockNumber,
			"txHash", log.TxHash.Hex(),
			"contract", log.Address.Hex())

		// Parse indexed topics
		var destChainSelector uint64
		var sender common.Address
		var messageID [32]byte

		// Explicitly check for the expected number of topics
		if len(log.Topics) < 4 {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("CCIPMessageSent event has insufficient topics",
				"expected", 4,
				"actual", len(log.Topics),
				"blockNumber", log.BlockNumber,
				"txHash", log.TxHash.Hex())
			continue // to next message
		}

		destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
		sender = common.BytesToAddress(log.Topics[2][12:])              // Last 20 bytes for address
		copy(messageID[:], log.Topics[3][:])                            // Full 32 bytes

		r.lggr.Debugw("Event details",
			"sourceChainSelector", r.chainSelector,
			"destChainSelector", destChainSelector,
			"sender", sender,
			protocol.LogKeyMessageID, protocol.Bytes32(messageID).String())

		// Parse the event data using the cached ABI
		event := &onramp.OnRampCCIPMessageSent{}
		event.DestChainSelector = destChainSelector
		event.MessageId = messageID
		event.Sender = sender
		err := r.onRampABI.UnpackIntoInterface(event, "CCIPMessageSent", log.Data)
		if err != nil {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("Failed to unpack CCIPMessageSent event payload", "error", err)
			continue // to next message
		}
		r.lggr.Debugw("OnRamp Event Structure",
			"destChainSelector", event.DestChainSelector,
			"sender", event.Sender,
			protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String(),
			"ReceiptsCount", len(event.Receipts),
			"verifierBlobsCount", len(event.VerifierBlobs))

		// Check minimum receipt count: at least 1 CCV + executor + network fees = 3 receipts
		if len(event.Receipts) < 3 {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("Insufficient receipts. Expected at least 3 (1 CCV + executor + network fees)",
				"count", len(event.Receipts),
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
			continue // to next message
		}

		for i, vr := range event.Receipts {
			r.lggr.Debugw("Receipt",
				"index", i,
				"issuer", vr.Issuer.Hex(),
				"destGasLimit", vr.DestGasLimit,
				"destBytesOverhead", vr.DestBytesOverhead,
				"feeTokenAmount", vr.FeeTokenAmount.String(),
				"extraArgs", common.Bytes2Hex(vr.ExtraArgs))
		}

		// Log executor receipt
		executorReceipt := event.Receipts[len(event.Receipts)-2]
		r.lggr.Debugw("Executor Receipt",
			"issuer", executorReceipt.Issuer.Hex(),
			"destGasLimit", executorReceipt.DestGasLimit,
			"destBytesOverhead", executorReceipt.DestBytesOverhead,
			"feeTokenAmount", executorReceipt.FeeTokenAmount.String(),
			"extraArgs", common.Bytes2Hex(executorReceipt.ExtraArgs))

		r.lggr.Debugw("Decoding encoded message",
			"encodedMessageLength", len(event.EncodedMessage),
			protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
		decodedMsg, err := protocol.DecodeMessage(event.EncodedMessage)
		if err != nil {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("Failed to decode message", "error", err, "rawMessage", event.EncodedMessage)
			continue // to next message
		}
		r.lggr.Debugw("Decoded message",
			"message", decodedMsg)

		// Validate that ccvAndExecutorHash is not zero - it's required
		if decodedMsg.CcvAndExecutorHash == (protocol.Bytes32{}) {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("ccvAndExecutorHash is zero in decoded message",
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String(),
				"blockNumber", log.BlockNumber)
			continue // to next message
		}

		if decodedMsg.SourceChainSelector != r.chainSelector {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("source chain selector must match the value configured — critical invariant violated; escalate immediately",
				"expected", r.chainSelector,
				"actual", decodedMsg.SourceChainSelector,
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
			continue // ensure we never process this msg
		}

		if !decodedMsg.OnRampAddress.Equal(expectedSourceAddressBytes(r.onRampAddress)) {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("onRampAddress must match the value configured — critical invariant violated; escalate immediately",
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
			continue // ensure we never process this msg
		}

		if !decodedMsg.Sender.Equal(expectedSourceAddressBytes(event.Sender)) {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("sender must match the value emitted from the on-chain event. This should never happen.", "sender", protocol.ByteSlice(event.Sender[:]).String())
			continue // ensure we never process this msg
		}

		if decodedMsg.MustMessageID() != event.MessageId {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("computed messageID must match the value emitted from the on-chain event — critical invariant violated; escalate immediately",
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
			continue // ensure we never process this msg
		}

		if decodedMsg.DestChainSelector != protocol.ChainSelector(event.DestChainSelector) {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("destination chain selector must match the value emitted from the on-chain event. This should never happen", protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String())
			continue // ensure we never process this msg
		}

		allReceipts := receiptBlobsFromEvent(event.Receipts, event.VerifierBlobs) // Validate the receipt structure matches expectations
		// Validate ccvAndExecutorHash
		if err := protocol.ValidateCCVAndExecutorHash(*decodedMsg, allReceipts); err != nil {
			r.onCriticalInvariant(ctx)
			r.lggr.Errorw("ccvAndExecutorHash validation failed",
				"error", err,
				protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String(),
				"blockNumber", log.BlockNumber)
			continue // to next message
		}

		// Some providers include the source-block time in their log response. Keep an
		// omitted timestamp unavailable instead of inventing an epoch time or fetching a block.
		var blockTimestamp time.Time
		if log.BlockTimestamp > 0 {
			blockTimestamp = time.Unix(int64(log.BlockTimestamp), 0).UTC() // #nosec G115 -- chain timestamps are within int64 range
		}
		results = append(results, protocol.MessageSentEvent{
			MessageID:      event.MessageId,
			Message:        *decodedMsg,
			Receipts:       allReceipts, // Keep original order from OnRamp event
			BlockNumber:    log.BlockNumber,
			BlockHash:      log.BlockHash.Bytes(),
			TxHash:         log.TxHash.Bytes(),
			FeeToken:       event.FeeToken.Bytes(),
			BlockTimestamp: blockTimestamp,
		})
	}
	return results
}

// LatestAndFinalizedBlock returns the latest and finalized block headers.
// Implements chainaccess.HeadTracker interface.
func (r *SourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	return r.headTrackerBlocks(ctx)
}

// LatestSafeBlock returns the latest safe block header.
// Returns nil without an error when the underlying chain does not support the safe tag.
// Implements chainaccess.HeadTracker interface.
func (r *SourceReader) LatestSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
	return r.headTrackerSafeBlock(ctx)
}

// headTrackerBlocks returns the head tracker's latest and finalized block headers.
func (r *sourceReaderCore) headTrackerBlocks(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	latestHead, finalizedHead, err := r.headTracker.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest and finalized blocks: %w", err)
	}

	if latestHead == nil || finalizedHead == nil {
		return nil, nil, fmt.Errorf("received nil head from tracker")
	}

	if latestHead.Number < 0 || finalizedHead.Number < 0 {
		return nil, nil, fmt.Errorf("block number cannot be negative: latest=%d, finalized=%d", latestHead.Number, finalizedHead.Number)
	}

	latest = &protocol.BlockHeader{
		Number:     uint64(latestHead.Number),
		Hash:       protocol.Bytes32(latestHead.Hash),
		ParentHash: protocol.Bytes32(latestHead.ParentHash),
		Timestamp:  latestHead.Timestamp,
	}

	finalized = &protocol.BlockHeader{
		Number:     uint64(finalizedHead.Number),
		Hash:       protocol.Bytes32(finalizedHead.Hash),
		ParentHash: protocol.Bytes32(finalizedHead.ParentHash),
		Timestamp:  finalizedHead.Timestamp,
	}

	return latest, finalized, nil
}

// headTrackerSafeBlock returns the head tracker's safe block header, nil when the chain does not
// support the safe tag.
func (r *sourceReaderCore) headTrackerSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
	safeHead, err := r.headTracker.LatestSafeBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get safe block: %w", err)
	}
	if safeHead == nil {
		return nil, nil
	}
	if safeHead.Number < 0 {
		return nil, fmt.Errorf("safe block number cannot be negative: %d", safeHead.Number)
	}
	return &protocol.BlockHeader{
		Number:     uint64(safeHead.Number),
		Hash:       protocol.Bytes32(safeHead.Hash),
		ParentHash: protocol.Bytes32(safeHead.ParentHash),
		Timestamp:  safeHead.Timestamp,
	}, nil
}

// GetRMNCursedSubjects queries this source chain's RMN Remote contract.
// Implements SourceReader and chainaccess.RMNCurseReader interfaces.
func (r *sourceReaderCore) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	// Resolve the RMN Remote caller lazily (first call derives it on-chain) so construction
	// performs no RPC and a transient derivation failure is surfaced here to be retried.
	caller, err := r.rmnRemoteCaller.Value(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve RMN Remote caller: %w", err)
	}
	// Use the common helper function from cursechecker package
	// This avoids code duplication with EVMDestinationReader
	return rmnremotereader.EVMReadRMNCursedSubjects(ctx, caller)
}

// receiptBlobsFromEvent converts OnRamp event receipts to protocol.ReceiptWithBlob format.
// It pairs each receipt with its corresponding verifier blob (if any).
func receiptBlobsFromEvent(eventReceipts []onramp.OnRampReceipt, verifierBlobs [][]byte) []protocol.ReceiptWithBlob {
	receipts := make([]protocol.ReceiptWithBlob, len(eventReceipts))
	for i, vr := range eventReceipts {
		var blob []byte
		// Only CCV receipts (first N receipts where N = len(verifierBlobs)) have blobs
		if i < len(verifierBlobs) {
			blob = verifierBlobs[i]
		}

		issuerAddr, _ := protocol.NewUnknownAddressFromHex(vr.Issuer.Hex())
		receipts[i] = protocol.ReceiptWithBlob{
			Issuer:            issuerAddr,
			DestGasLimit:      uint64(vr.DestGasLimit),
			DestBytesOverhead: vr.DestBytesOverhead,
			Blob:              blob,
			ExtraArgs:         vr.ExtraArgs,
			FeeTokenAmount:    vr.FeeTokenAmount,
		}
	}
	return receipts
}

// expectedSourceAddressBytes returns the byte representation of a source address as emitted by the on-chain event.
func expectedSourceAddressBytes(sourceAddress common.Address) []byte {
	return common.LeftPadBytes(sourceAddress[:], 32)
}
