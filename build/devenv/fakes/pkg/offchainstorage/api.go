package offchainstorage

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

type OffChainStorageAPI struct {
	mu       sync.RWMutex
	messages []protocol.QueryResponse
}

func NewOffChainStorageAPI() *OffChainStorageAPI {
	return &OffChainStorageAPI{
		messages: make([]protocol.QueryResponse, 0),
	}
}

// AddMessage adds a message to the fake storage
func (o *OffChainStorageAPI) AddMessage(response protocol.QueryResponse) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, response)
}

// AddMessages adds multiple messages to the fake storage
func (o *OffChainStorageAPI) AddMessages(responses []protocol.QueryResponse) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, responses...)
}

// GenerateTestMessage creates a test message with the given parameters
func GenerateTestMessage(messageNumber int, timestamp int64, sourceChain, destChain protocol.ChainSelector) protocol.QueryResponse {
	sourceAddr, _ := protocol.RandomAddress()
	destAddr, _ := protocol.RandomAddress()
	onRampAddr, _ := protocol.RandomAddress()
	offRampAddr, _ := protocol.RandomAddress()
	sender, _ := protocol.RandomAddress()
	receiver, _ := protocol.RandomAddress()

	// #nosec G115 -- integer conversions are safe: messageNumber is controlled
	message := protocol.Message{
		Version:              protocol.MessageVersion,
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		Nonce:                protocol.Nonce(messageNumber),
		OnRampAddressLength:  uint8(len(onRampAddr)),
		OnRampAddress:        onRampAddr,
		OffRampAddressLength: uint8(len(offRampAddr)),
		OffRampAddress:       offRampAddr,
		Finality:             10,
		SenderLength:         uint8(len(sender)),
		Sender:               sender,
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver,
		DataLength:           0,
		Data:                 []byte{},
		TokenTransferLength:  0,
		TokenTransfer:        []byte{},
		DestBlobLength:       0,
		DestBlob:             []byte{},
	}

	messageID, _ := message.MessageID()

	ccvData := protocol.CCVData{
		SourceVerifierAddress: sourceAddr,
		DestVerifierAddress:   destAddr,
		Message:               message,
		Nonce:                 message.Nonce,
		SourceChainSelector:   message.SourceChainSelector,
		DestChainSelector:     message.DestChainSelector,
		MessageID:             messageID,
		CCVData:               []byte{},
		BlobData:              []byte{},
		ReceiptBlobs:          []protocol.ReceiptWithBlob{},
		Timestamp:             timestamp,
	}

	return protocol.QueryResponse{
		Timestamp: &timestamp,
		Data:      ccvData,
	}
}

// Register registers the API endpoints with the fake service
func (o *OffChainStorageAPI) Register() error {
	err := fake.Func("GET", "/messages", func(ctx *gin.Context) {
		sinceStr := ctx.Query("since")
		since := int64(0)
		if sinceStr != "" {
			parsed, err := strconv.ParseInt(sinceStr, 10, 64)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid since parameter"})
				return
			}
			since = parsed
		}

		o.mu.RLock()
		defer o.mu.RUnlock()

		// Filter messages by timestamp
		var filtered []protocol.QueryResponse
		for _, msg := range o.messages {
			if msg.Data.Timestamp != 0 && msg.Data.Timestamp >= since {
				filtered = append(filtered, msg)
			}
		}

		ctx.JSON(http.StatusOK, filtered)
	})
	if err != nil {
		return err
	}

	err = fake.Func("POST", "/message", func(ctx *gin.Context) {
		var msg protocol.QueryResponse
		if err := ctx.ShouldBindJSON(&msg); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		o.AddMessage(msg)
		ctx.JSON(200, gin.H{"message": "message received"})
	})
	if err != nil {
		return err
	}

	return nil
}
