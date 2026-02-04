package sourcereader

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/rmnremotereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/validate"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

// Compile-time checks to ensure EVMSourceReader implements the SourceReader interface.
var (
	_ chainaccess.SourceReader = (*EVMSourceReader)(nil)
)

type EVMSourceReader struct {
	chainClient          client.Client
	headTracker          heads.Tracker
	onRampAddress        common.Address
	rmnRemoteAddress     common.Address
	rmnRemoteCaller      rmn_remote.RMNRemoteCaller
	ccipMessageSentTopic string
	chainSelector        protocol.ChainSelector
	lggr                 logger.Logger
}

func NewEVMSourceReader(
	chainClient client.Client,
	headTracker heads.Tracker,
	onRampAddress common.Address,
	rmnRemoteAddress common.Address,
	ccipMessageSentTopic string,
	chainSelector protocol.ChainSelector,
	lggr logger.Logger,
) (chainaccess.SourceReader, error) {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(chainClient, "chainClient")
	appendIfNil(headTracker, "headTracker")
	appendIfNil(lggr, "logger")

	if onRampAddress == (common.Address{}) {
		errs = append(errs, fmt.Errorf("onRampAddress is not set"))
	}
	if rmnRemoteAddress == (common.Address{}) {
		errs = append(errs, fmt.Errorf("rmnRemoteAddress is not set"))
	}
	if ccipMessageSentTopic == "" {
		errs = append(errs, fmt.Errorf("ccipMessageSentTopic is not set"))
	}
	if chainSelector == 0 {
		errs = append(errs, fmt.Errorf("chainSelector is not set"))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Bind to RMN Remote contract
	rmnRemoteCaller, err := rmn_remote.NewRMNRemoteCaller(rmnRemoteAddress, chainClient)
	if err != nil {
		return nil, fmt.Errorf("failed to bind RMN Remote contract at %s: %w",
			rmnRemoteAddress.Hex(), err)
	}

	return &EVMSourceReader{
		chainClient:          chainClient,
		headTracker:          headTracker,
		onRampAddress:        onRampAddress,
		rmnRemoteAddress:     rmnRemoteAddress,
		rmnRemoteCaller:      *rmnRemoteCaller,
		ccipMessageSentTopic: ccipMessageSentTopic,
		chainSelector:        chainSelector,
		lggr:                 lggr,
	}, nil
}

// GetBlocksHeaders TODO: Should use batch requests for efficiency ticket: CCIP-7766.
func (r *EVMSourceReader) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	headers := make(map[*big.Int]protocol.BlockHeader)
	for _, blockNumber := range blockNumbers {
		header, err := r.chainClient.HeadByNumber(ctx, blockNumber)
		if err != nil {
			r.lggr.Warnw("Failed to get block header", "blockNumber", blockNumber.String(), "error", err)
			continue
		}
		if header.Number < 0 {
			return nil, fmt.Errorf("block number cannot be negative: %d", header.Number)
		}
		headers[blockNumber] = protocol.BlockHeader{
			Number:     uint64(header.Number),
			Hash:       protocol.Bytes32(header.Hash),
			ParentHash: protocol.Bytes32(header.ParentHash),
			Timestamp:  header.Timestamp,
		}
	}
	return headers, nil
}

// FetchMessageSentEvents returns MessageSentEvents in the given block range.
// The toBlock parameter can be nil to query up to the latest block.
func (r *EVMSourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	rangeQuery := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   toBlock,
		Addresses: []common.Address{r.onRampAddress},
		Topics:    [][]common.Hash{{common.HexToHash(r.ccipMessageSentTopic)}},
	}
	logs, err := r.chainClient.FilterLogs(ctx, rangeQuery)
	if err != nil {
		r.lggr.Warnw("Failed to filter logs", "error", err)
		return nil, err
	}

	results := make([]protocol.MessageSentEvent, 0, len(logs))

	// Process found events
	for _, log := range logs {
		r.lggr.Infow("Found CCIPMessageSent event!",
			"chainSelector", r.chainSelector,
			"blockNumber", log.BlockNumber,
			"txHash", log.TxHash.Hex(),
			"contract", log.Address.Hex())

		// Parse indexed topics
		var destChainSelector uint64
		var sender common.Address
		var messageID [32]byte

		if len(log.Topics) >= 4 {
			destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
			sender = common.BytesToAddress(log.Topics[2][12:])              // Last 20 bytes for address
			copy(messageID[:], log.Topics[3][:])                            // Full 32 bytes

			r.lggr.Infow("Event details",
				"sourceChainSelector", r.chainSelector,
				"destChainSelector", destChainSelector,
				"sender", sender,
				"messageId", common.Bytes2Hex(messageID[:]))
		}

		// Parse the event data using the ABI
		event := &onramp.OnRampCCIPMessageSent{}
		event.DestChainSelector = destChainSelector
		event.MessageId = messageID
		event.Sender = sender
		abi, err := onramp.OnRampMetaData.GetAbi()
		if err != nil {
			r.lggr.Errorw("Failed to get ABI", "error", err)
			continue // to next message
		}
		err = abi.UnpackIntoInterface(event, "CCIPMessageSent", log.Data)
		if err != nil {
			r.lggr.Errorw("Failed to unpack CCIPMessageSent event payload", "error", err)
			continue // to next message
		}
		// Log the event structure using the fixed bindings
		r.lggr.Infow("OnRamp Event Structure",
			"destChainSelector", event.DestChainSelector,
			"sender", event.Sender,
			"messageId", common.Bytes2Hex(event.MessageId[:]),
			"ReceiptsCount", len(event.Receipts),
			"verifierBlobsCount", len(event.VerifierBlobs))

		if len(event.Receipts) < 2 {
			// The executor receipt is at Receipts[len-2], so we need at least two receipts
			r.lggr.Errorw("Executor receipt is missing.", "count", len(event.Receipts))
			continue // to next message
		}

		// Log verifier receipts
		for i, vr := range event.Receipts {
			r.lggr.Infow("Verifier Receipt",
				"index", i,
				"issuer", vr.Issuer.Hex(),
				"destGasLimit", vr.DestGasLimit,
				"destBytesOverhead", vr.DestBytesOverhead,
				"feeTokenAmount", vr.FeeTokenAmount.String(),
				"extraArgs", common.Bytes2Hex(vr.ExtraArgs))
		}

		// Log executor receipt
		executorReceipt := event.Receipts[len(event.Receipts)-2]
		r.lggr.Infow("Executor Receipt",
			"issuer", executorReceipt.Issuer.Hex(),
			"destGasLimit", executorReceipt.DestGasLimit,
			"destBytesOverhead", executorReceipt.DestBytesOverhead,
			"feeTokenAmount", executorReceipt.FeeTokenAmount.String(),
			"extraArgs", common.Bytes2Hex(executorReceipt.ExtraArgs))

		r.lggr.Infow("Decoding encoded message",
			"encodedMessageLength", len(event.EncodedMessage),
			"messageId", common.Bytes2Hex(event.MessageId[:]))
		decodedMsg, err := protocol.DecodeMessage(event.EncodedMessage)
		if err != nil {
			r.lggr.Errorw("Failed to decode message", "error", err)
			continue // to next message
		}
		r.lggr.Infow("Decoded message",
			"message", decodedMsg)

		// Validate that ccvAndExecutorHash is not zero - it's required
		if decodedMsg.CcvAndExecutorHash == (protocol.Bytes32{}) {
			r.lggr.Errorw("ccvAndExecutorHash is zero in decoded message",
				"messageID", common.Bytes2Hex(event.MessageId[:]),
				"blockNumber", log.BlockNumber)
			continue // to next message
		}

		if !decodedMsg.OnRampAddress.Equal(expectedSourceAddressBytes(r.onRampAddress)) {
			r.lggr.Errorw("onRampAddress must match the value configured. This should never happen, if it does something is seriously wrong. Escalate immediately", "messageId", common.Bytes2Hex(event.MessageId[:]))
			continue // to next message
		}

		if !decodedMsg.Sender.Equal(expectedSourceAddressBytes(event.Sender)) {
			r.lggr.Errorw("sender must match the value emitted from the on-chain event. This should never happen.", "messageId", common.Bytes2Hex(event.Sender[:]))
			continue // to next message
		}

		if decodedMsg.MustMessageID() != event.MessageId {
			r.lggr.Errorw("computed messageID must match the value emitted from the on-chain event. This should never happen, if it does escalate immediately.", "messageId", common.Bytes2Hex(event.MessageId[:]))
			continue // to the next message
		}

		if decodedMsg.DestChainSelector != protocol.ChainSelector(event.DestChainSelector) {
			r.lggr.Errorw("destination chain selector must match the value emited from the on-chain event. This should never happen", "messageId", common.Bytes2Hex(event.MessageId[:]))
			continue // to the next message
		}

		allReceipts := receiptBlobsFromEvent(event.Receipts, event.VerifierBlobs) // Validate the receipt structure matches expectations
		// Validate ccvAndExecutorHash
		if err := validate.ValidateCCVAndExecutorHash(*decodedMsg, allReceipts); err != nil {
			r.lggr.Errorw("ccvAndExecutorHash validation failed",
				"error", err,
				"messageID", common.Bytes2Hex(event.MessageId[:]),
				"blockNumber", log.BlockNumber)
			continue // to next message
		}

		results = append(results, protocol.MessageSentEvent{
			MessageID:   protocol.Bytes32(event.MessageId),
			Message:     *decodedMsg,
			Receipts:    allReceipts, // Keep original order from OnRamp event
			BlockNumber: log.BlockNumber,
			TxHash:      protocol.ByteSlice(log.TxHash.Bytes()),
		})
	}
	return results, nil
}

// LatestAndFinalizedBlock returns the latest and finalized block headers.
// Implements chainaccess.HeadTracker interface.
func (r *EVMSourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
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

// GetRMNCursedSubjects queries this source chain's RMN Remote contract.
// Implements SourceReader and cursechecker.RMNCurseReader interfaces.
func (r *EVMSourceReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	// Use the common helper function from cursechecker package
	// This avoids code duplication with EVMDestinationReader
	return rmnremotereader.EVMReadRMNCursedSubjects(ctx, r.rmnRemoteCaller)
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
