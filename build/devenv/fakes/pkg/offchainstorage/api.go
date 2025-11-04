package offchainstorage

import (
	"net/http"
	"strconv"
	"sync"
	"time"

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

// AddMessage adds a message to the fake storage.
func (o *OffChainStorageAPI) AddMessage(response protocol.QueryResponse) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, response)
}

// AddMessages adds multiple messages to the fake storage.
func (o *OffChainStorageAPI) AddMessages(responses []protocol.QueryResponse) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, responses...)
}

// Register registers the API endpoints with the fake service.
func (o *OffChainStorageAPI) Register() error {
	err := fake.Func("GET", "/messages", func(ctx *gin.Context) {
		sinceStr := ctx.Query("since")
		since := time.Time{} // zero value for time.Time
		if sinceStr != "" {
			parsed, err := strconv.ParseInt(sinceStr, 10, 64)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid since parameter"})
				return
			}
			since = time.UnixMilli(parsed)
		}

		o.mu.RLock()
		defer o.mu.RUnlock()

		// Filter messages by timestamp
		var filtered []protocol.QueryResponse
		for _, msg := range o.messages {
			if !msg.Data.Timestamp.IsZero() && !msg.Data.Timestamp.Before(since) {
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
