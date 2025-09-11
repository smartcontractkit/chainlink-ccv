package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type ScheduledDataPusher struct {
	messageChan chan types.MessageWithCCVData
	lggr        logger.Logger
}

func NewScheduledDataPusher(lggr logger.Logger) *ScheduledDataPusher {
	return &ScheduledDataPusher{
		lggr:        lggr,
		messageChan: make(chan types.MessageWithCCVData),
	}
}

// SubscribeMessages implements the CcvDataReader interface.
// It will return a channel of MessageWithCCVData objects.
func (sdp *ScheduledDataPusher) SubscribeMessages() (chan types.MessageWithCCVData, error) {
	return sdp.messageChan, nil
}

// Run will push messages to the channel every 10 seconds
func (sdp *ScheduledDataPusher) Run(ctx context.Context, d time.Duration) {
	//timestamp := time.Now().Unix()
	//storage, err := storageaccess.NewAggregatorReader("aggregator:50051", sdp.lggr, timestamp)
	//if err != nil {
	//	sdp.lggr.Errorw("Failed to create storage writer", "error", err)
	//	os.Exit(1)
	//}

	ticker := time.NewTicker(d)
	defer ticker.Stop()

	messageCounter := uint64(1)

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, stop the pusher
			close(sdp.messageChan)
			return
		case <-ticker.C:
			//sdp.lggr.Infow("Checking aggregator for messages")
			//aggregatorPayload, err := storage.ReadCCVData(ctx)
			//if err != nil {
			//	sdp.lggr.Errorw("Failed to read CCV data from aggregator", "error", err)
			//	continue
			//}
			//for _, ccvdata := range aggregatorPayload {
			//	sdp.lggr.Infow("verifier commit found")
			//	sdp.messageChan <- types.MessageWithCCVData{
			//		CCVData:           []protocol.CCVData{ccvdata.Data},
			//		VerifiedTimestamp: 0,
			//		Message:           ccvdata.Data.Message,
			//	}
			//}
			//timestamp = time.Now().Unix()

			// Generate and send a mock message
			mockMessage := sdp.createMockMessage(messageCounter)
			sdp.lggr.Infow("Generating mock message", "messageCounter", messageCounter, "timestamp", mockMessage.VerifiedTimestamp)
			sdp.messageChan <- mockMessage
			// Message sent successfully
			messageCounter++
		}
	}
}

// createMockMessage creates a mock MessageWithCCVData for testing
func (sdp *ScheduledDataPusher) createMockMessage(counter uint64) types.MessageWithCCVData {
	// Create mock sender and receiver addresses
	senderAddr, _ := protocol.NewUnknownAddressFromHex("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
	receiverAddr, _ := protocol.NewUnknownAddressFromHex("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")
	onRampAddr, _ := protocol.NewUnknownAddressFromHex("0x0B306BF915C4d645ff596e518fAf3F9669b97016")
	offRampAddr, _ := protocol.NewUnknownAddressFromHex("0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
	sourceSel := protocol.ChainSelector(3379446385462418246)
	destSel := protocol.ChainSelector(12922642891491394802)
	timestamp := time.Now().Unix()

	// Create a mock message
	message, _ := protocol.NewMessage(
		sourceSel,
		destSel,
		protocol.SeqNum(counter),
		onRampAddr,
		offRampAddr,
		0, // finality
		senderAddr,
		receiverAddr,
		[]byte{}, // dest blob
		[]byte(fmt.Sprintf("mock-data-%d", counter)), // data
		nil, // empty token transfer
	)

	id, _ := message.MessageID()
	// Create mock CCV data
	ccvData := []protocol.CCVData{
		{
			SourceVerifierAddress: senderAddr,
			DestVerifierAddress:   offRampAddr,
			CCVData:               []byte(fmt.Sprintf("mock-ccv-%d", counter)),
			BlobData:              []byte{},
			Message:               *message,
			SequenceNumber:        protocol.SeqNum(counter),
			SourceChainSelector:   sourceSel,
			DestChainSelector:     destSel,
			Timestamp:             timestamp,
			MessageID:             id,
		},
	}

	return types.MessageWithCCVData{
		CCVData:           ccvData,
		Message:           *message,
		VerifiedTimestamp: timestamp,
	}
}
