package sourcereader

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier"
)

type EVMSourceReader struct {
	chainClient          client.Client
	headTracker          chainaccess.HeadTracker
	contractAddress      common.Address
	ccipMessageSentTopic string
	chainSelector        protocol.ChainSelector
	lggr                 logger.Logger
}

func NewEVMSourceReader(
	chainClient client.Client,
	headTracker chainaccess.HeadTracker,
	contractAddress common.Address,
	ccipMessageSentTopic string,
	chainSelector protocol.ChainSelector,
	lggr logger.Logger,
) (verifiertypes.SourceReader, error) {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(chainClient, "chainClient")
	appendIfNil(headTracker, "headTracker")
	appendIfNil(lggr, "logger")

	if contractAddress == (common.Address{}) {
		errs = append(errs, fmt.Errorf("contractAddress is not set"))
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

	return &EVMSourceReader{
		chainClient:          chainClient,
		headTracker:          headTracker,
		contractAddress:      contractAddress,
		ccipMessageSentTopic: ccipMessageSentTopic,
		chainSelector:        chainSelector,
		lggr:                 lggr,
	}, nil
}

// GetBlocksHeaders TODO: Should use batch requests for efficiency ticket: CCIP-7766.
func (r *EVMSourceReader) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	// Get current finalized block to populate FinalizedBlockNumber field
	_, finalized, err := r.headTracker.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

	// If safe block not supported, safeBlockNum remains 0

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
			FinalizedBlockNumber: finalized.Number,
		}
	}
	return headers, nil
}

// GetBlockHeaderByHash returns a block header by its hash.
// Required for walking back parent chain during LCA finding in reorg detection.
func (r *EVMSourceReader) GetBlockHeaderByHash(ctx context.Context, hash protocol.Bytes32) (*protocol.BlockHeader, error) {
	// Get current finalized block to populate FinalizedBlockNumber field
	_, finalized, err := r.headTracker.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

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

	return &protocol.BlockHeader{
		Number:               uint64(header.Number),
		Hash:                 protocol.Bytes32(header.Hash),
		ParentHash:           protocol.Bytes32(header.ParentHash),
		Timestamp:            header.Timestamp,
		FinalizedBlockNumber: finalized.Number,
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

// VerificationTasks returns the channel where new message events are delivered.
func (r *EVMSourceReader) VerificationTasks(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifiertypes.VerificationTask, error) {
	rangeQuery := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   toBlock,
		Addresses: []common.Address{r.contractAddress},
		Topics:    [][]common.Hash{{common.HexToHash(r.ccipMessageSentTopic)}},
	}
	logs, err := r.chainClient.FilterLogs(ctx, rangeQuery)
	if err != nil {
		r.lggr.Warnw("⚠️ Failed to filter logs", "error", err)
		return nil, err
	}

	results := make([]verifiertypes.VerificationTask, 0, len(logs))

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
			r.lggr.Errorw("❌ Failed to get ABI", "error", err)
			continue // to next message
		}
		err = abi.UnpackIntoInterface(event, "CCIPMessageSent", log.Data)
		if err != nil {
			r.lggr.Errorw("❌ Failed to unpack CCIPMessageSent event payload", "error", err)
			continue // to next message
		}
		// Log the event structure using the fixed bindings
		r.lggr.Infow("📋 OnRamp Event Structure",
			"destChainSelector", event.DestChainSelector,
			"nonce", event.SequenceNumber,
			"messageId", common.Bytes2Hex(event.MessageId[:]),
			"ReceiptsCount", len(event.Receipts),
			"verifierBlobsCount", len(event.VerifierBlobs))

		if len(event.Receipts) < 1 {
			// The executor receipt is at Receipts[len-1], so we need at least one receipt
			r.lggr.Errorw("❌ Executor receipt is missing.", "count", len(event.Receipts))
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
		r.lggr.Infow("📋 Executor Receipt",
			"issuer", executorReceipt.Issuer.Hex(),
			"destGasLimit", executorReceipt.DestGasLimit,
			"destBytesOverhead", executorReceipt.DestBytesOverhead,
			"feeTokenAmount", executorReceipt.FeeTokenAmount.String(),
			"extraArgs", common.Bytes2Hex(executorReceipt.ExtraArgs))

		r.lggr.Infow("📋 Decoding encoded message",
			"encodedMessageLength", len(event.EncodedMessage),
			"messageId", common.Bytes2Hex(event.MessageId[:]))
		decodedMsg, err := protocol.DecodeMessage(event.EncodedMessage)
		if err != nil {
			r.lggr.Errorw("❌ Failed to decode message", "error", err)
			continue // to next message
		}
		r.lggr.Infow("📋 Decoded message",
			"message", decodedMsg)

		// Create receipt blobs from verifier receipts and receipt blobs
		receiptBlobs := make([]protocol.ReceiptWithBlob, 0, len(event.Receipts)+1)

		if len(event.Receipts) == 0 {
			r.lggr.Errorw("❌ No verifier receipts found")
			continue // to next message
		}
		// Process verifier receipts
		for i, vr := range event.Receipts {
			var blob []byte
			if i < len(event.VerifierBlobs) && len(event.VerifierBlobs[i]) > 0 {
				blob = event.VerifierBlobs[i]
			} else {
				r.lggr.Infow("⚠️ Empty or missing receipt blob",
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

			r.lggr.Infow("📋 Processed verifier receipt",
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

		r.lggr.Infow("📋 Processed executor receipt",
			"issuer", executorReceipt.Issuer.Hex())

		// Create verification task
		results = append(results, verifiertypes.VerificationTask{
			Message:      *decodedMsg,
			ReceiptBlobs: receiptBlobs,
			BlockNumber:  log.BlockNumber,
		})
	}
	return results, nil
}
