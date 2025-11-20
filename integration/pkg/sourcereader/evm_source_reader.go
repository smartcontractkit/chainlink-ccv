package sourcereader

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/rmnremotereader"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
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
	// Get current finalized block to populate FinalizedBlockNumber field
	_, finalizedHeader, err := r.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

	headers := make(map[*big.Int]protocol.BlockHeader)
	for _, blockNumber := range blockNumbers {
		header, err := r.chainClient.HeadByNumber(ctx, blockNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get block %s: %w", blockNumber.String(), err)
		}
		if header.Number < 0 {
			return nil, fmt.Errorf("block number cannot be negative: %d", header.Number)
		}
		headers[blockNumber] = protocol.BlockHeader{
			Number:               uint64(header.Number),
			Hash:                 protocol.Bytes32(header.Hash),
			ParentHash:           protocol.Bytes32(header.ParentHash),
			Timestamp:            header.Timestamp,
			FinalizedBlockNumber: finalizedHeader.Number,
		}
	}
	return headers, nil
}

// GetBlockHeaderByHash returns a block header by its hash.
// Required for walking back parent chain during LCA finding in reorg detection.
func (r *EVMSourceReader) GetBlockHeaderByHash(ctx context.Context, hash protocol.Bytes32) (*protocol.BlockHeader, error) {
	// Convert protocol.Bytes32 to common.Hash
	var ethHash common.Hash
	copy(ethHash[:], hash[:])

	header, err := r.chainClient.HeadByHash(ctx, ethHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block by hash %s: %w", ethHash.Hex(), err)
	}

	if header == nil {
		return nil, nil // Block not found
	}

	if header.Number < 0 {
		return nil, fmt.Errorf("block number cannot be negative: %d", header.Number)
	}

	finalizedBlockNum := header.LatestFinalizedHead().BlockNumber()
	if finalizedBlockNum < 0 {
		return nil, fmt.Errorf("finalized block number cannot be negative: %d", finalizedBlockNum)
	}

	return &protocol.BlockHeader{
		Number:               uint64(header.Number),
		Hash:                 protocol.Bytes32(header.Hash),
		ParentHash:           protocol.Bytes32(header.ParentHash),
		Timestamp:            header.Timestamp,
		FinalizedBlockNumber: uint64(finalizedBlockNum),
	}, nil
}

// BlockTime returns the timestamp of a given block.
func (r *EVMSourceReader) BlockTime(ctx context.Context, block *big.Int) (uint64, error) {
	hdr, err := r.chainClient.HeaderByNumber(ctx, block)
	if err != nil {
		return 0, fmt.Errorf("failed to get block header for block %s: %w", block.String(), err)
	}
	return hdr.Time, nil
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
		r.lggr.Infow("🎉 Found CCIPMessageSent event!",
			"chainSelector", r.chainSelector,
			"blockNumber", log.BlockNumber,
			"txHash", log.TxHash.Hex(),
			"contract", log.Address.Hex())

		// Parse indexed topics
		var destChainSelector uint64
		var nonce uint64
		var messageID [32]byte

		if len(log.Topics) >= 4 {
			destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
			nonce = binary.BigEndian.Uint64(log.Topics[2][24:])             // Last 8 bytes
			copy(messageID[:], log.Topics[3][:])                            // Full 32 bytes

			r.lggr.Infow("📊 Event details",
				"sourceChainSelector", r.chainSelector,
				"destChainSelector", destChainSelector,
				"nonce", nonce,
				"messageId", common.Bytes2Hex(messageID[:]))
		}

		// Parse the event data using the ABI
		event := &onramp.OnRampCCIPMessageSent{}
		event.DestChainSelector = destChainSelector
		event.MessageId = messageID
		event.SequenceNumber = nonce
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
			"nonce", event.SequenceNumber,
			"messageId", common.Bytes2Hex(event.MessageId[:]),
			"ReceiptsCount", len(event.Receipts),
			"verifierBlobsCount", len(event.VerifierBlobs))

		if len(event.Receipts) < 1 {
			// The executor receipt is at Receipts[len-1], so we need at least one receipt
			r.lggr.Errorw("Executor receipt is missing.", "count", len(event.Receipts))
			continue // to next message
		}

		// Log verifier receipts
		for i, vr := range event.Receipts {
			r.lggr.Infow("🧾 Verifier Receipt",
				"index", i,
				"issuer", vr.Issuer.Hex(),
				"destGasLimit", vr.DestGasLimit,
				"destBytesOverhead", vr.DestBytesOverhead,
				"feeTokenAmount", vr.FeeTokenAmount.String(),
				"extraArgs", common.Bytes2Hex(vr.ExtraArgs))
		}

		// Log executor receipt
		executorReceipt := event.Receipts[len(event.Receipts)-1]
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

		// Create receipt blobs from verifier receipts and receipt blobs
		receiptBlobs := make([]protocol.ReceiptWithBlob, 0, len(event.Receipts)+1)

		if len(event.Receipts) == 0 {
			r.lggr.Errorw("No verifier receipts found")
			continue // to next message
		}
		// Process verifier receipts
		for i, vr := range event.Receipts {
			var blob []byte
			if i < len(event.VerifierBlobs) && len(event.VerifierBlobs[i]) > 0 {
				blob = event.VerifierBlobs[i]
			} else {
				r.lggr.Infow("Empty or missing receipt blob",
					"verifierIndex", i,
				)
			}

			issuerAddr, _ := protocol.NewUnknownAddressFromHex(vr.Issuer.Hex())
			receiptBlob := protocol.ReceiptWithBlob{
				Issuer:            issuerAddr,
				DestGasLimit:      vr.DestGasLimit,
				DestBytesOverhead: vr.DestBytesOverhead,
				Blob:              blob,
				ExtraArgs:         vr.ExtraArgs,
				FeeTokenAmount:    vr.FeeTokenAmount,
			}
			receiptBlobs = append(receiptBlobs, receiptBlob)

			r.lggr.Infow("Processed verifier receipt",
				"index", i,
				"issuer", vr.Issuer.Hex(),
				"blobLength", len(blob))
		}

		// Add executor receipt if available
		issuerAddr, _ := protocol.NewUnknownAddressFromHex(executorReceipt.Issuer.Hex())
		executorReceiptBlob := protocol.ReceiptWithBlob{
			Issuer:            issuerAddr,
			DestGasLimit:      executorReceipt.DestGasLimit,
			DestBytesOverhead: executorReceipt.DestBytesOverhead,
			Blob:              []byte{},
			ExtraArgs:         executorReceipt.ExtraArgs,
			FeeTokenAmount:    executorReceipt.FeeTokenAmount,
		}
		receiptBlobs = append(receiptBlobs, executorReceiptBlob)

		r.lggr.Infow("Processed executor receipt",
			"issuer", executorReceipt.Issuer.Hex())

		results = append(results, protocol.MessageSentEvent{
			DestChainSelector: protocol.ChainSelector(event.DestChainSelector),
			SequenceNumber:    event.SequenceNumber,
			MessageID:         protocol.Bytes32(event.MessageId),
			Message:           *decodedMsg,
			Receipts:          receiptBlobs,
			BlockNumber:       log.BlockNumber,
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
		Number:               uint64(latestHead.Number),
		Hash:                 protocol.Bytes32(latestHead.Hash),
		ParentHash:           protocol.Bytes32(latestHead.ParentHash),
		Timestamp:            latestHead.Timestamp,
		FinalizedBlockNumber: uint64(finalizedHead.Number),
	}

	finalized = &protocol.BlockHeader{
		Number:               uint64(finalizedHead.Number),
		Hash:                 protocol.Bytes32(finalizedHead.Hash),
		ParentHash:           protocol.Bytes32(finalizedHead.ParentHash),
		Timestamp:            finalizedHead.Timestamp,
		FinalizedBlockNumber: uint64(finalizedHead.Number),
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
