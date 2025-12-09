package v1

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
)

// VerifierResultsResponse represents the JSON response.
type VerifierResultsResponse struct {
	Results []VerifierResultResponse `json:"results"`
	Errors  []string                 `json:"errors,omitempty"`
}

// VerifierResultResponse represents a single verifier result in JSON format.
type VerifierResultResponse struct {
	Message                *MessageResponse `json:"message"`
	MessageCcvAddresses    []string         `json:"message_ccv_addresses,omitempty"`
	MessageExecutorAddress *string          `json:"message_executor_address,omitempty"`
	CcvData                string           `json:"ccv_data"` // hex-encoded bytes
	Metadata               *Metadata        `json:"metadata,omitempty"`
}

// MessageResponse represents a protocol.Message in JSON format.
type MessageResponse struct {
	Version             uint8   `json:"version"`
	SourceChainSelector uint64  `json:"source_chain_selector"`
	DestChainSelector   uint64  `json:"dest_chain_selector"`
	SequenceNumber      uint64  `json:"sequence_number"`
	OnRampAddress       string  `json:"on_ramp_address"`  // hex-encoded
	OffRampAddress      string  `json:"off_ramp_address"` // hex-encoded
	Finality            uint16  `json:"finality"`
	ExecutionGasLimit   uint32  `json:"execution_gas_limit"`
	CcipReceiveGasLimit uint32  `json:"ccip_receive_gas_limit"`
	CcvAndExecutorHash  string  `json:"ccv_and_executor_hash"`    // hex-encoded
	Sender              string  `json:"sender"`                   // hex-encoded
	Receiver            string  `json:"receiver"`                 // hex-encoded
	DestBlob            string  `json:"dest_blob"`                // hex-encoded
	TokenTransfer       *string `json:"token_transfer,omitempty"` // hex-encoded, optional
	Data                string  `json:"data"`                     // hex-encoded
}

// Metadata placeholder for future use.
type Metadata struct {
	// Add metadata fields as needed
}

// VerifierResultsHandler handles HTTP requests for verifier results.
type VerifierResultsHandler struct {
	lggr                  logger.Logger
	storage               *storage.OffchainStorage
	maxMessageIDsPerBatch int
}

func NewVerifierResultsHandler(
	lggr logger.Logger,
	storage *storage.OffchainStorage,
) *VerifierResultsHandler {
	return &VerifierResultsHandler{
		lggr:                  lggr,
		storage:               storage,
		maxMessageIDsPerBatch: 20,
	}
}

// Handle processes GET requests with message_ids as query parameters
// Expected query parameter format: ?message_ids=0x123abc,0x456def,...
func (h *VerifierResultsHandler) Handle(c *gin.Context) {
	// Get message_ids from query parameters
	messageIDsParam := c.Query("message_ids")
	if messageIDsParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message_ids query parameter is required"})
		return
	}

	// Split by comma to get individual message IDs
	messageIDStrings := strings.Split(messageIDsParam, ",")
	if len(messageIDStrings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message_ids cannot be empty"})
		return
	}

	if len(messageIDStrings) > h.maxMessageIDsPerBatch {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("too many message_ids: %d, maximum allowed: %d",
				len(messageIDStrings),
				h.maxMessageIDsPerBatch),
		})
		return
	}

	messageIDs := make([]protocol.Bytes32, 0, len(messageIDStrings))
	for _, msgIDStr := range messageIDStrings {
		// Trim whitespace and 0x prefix if present
		msgIDStr = strings.TrimSpace(msgIDStr)
		msgIDStr = strings.TrimPrefix(msgIDStr, "0x")

		// Decode hex string
		msgIDBytes, err := hex.DecodeString(msgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid message_id format: %s - %v", msgIDStr, err),
			})
			return
		}

		// Ensure it's 32 bytes
		if len(msgIDBytes) != 32 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("message_id must be 32 bytes, got %d", len(msgIDBytes)),
			})
			return
		}

		var msgID protocol.Bytes32
		copy(msgID[:], msgIDBytes)
		messageIDs = append(messageIDs, msgID)
	}

	// Call storage for efficient batch retrieval
	results, err := h.storage.ReadBatchCCVData(c.Request.Context(), messageIDs)
	if err != nil {
		h.lggr.Errorf("Failed to retrieve batch CCV data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve batch data"})
		return
	}

	// Process each message ID in order to maintain index correspondence
	jsonResults := make([]VerifierResultResponse, 0, len(messageIDs))
	errors := make([]string, 0)

	for _, messageID := range messageIDs {
		result, ok := results[messageID]
		if !ok {
			errors = append(errors, "message not found: "+hex.EncodeToString(messageID[:]))
			continue
		}

		// Convert protocol.Message to MessageResponse
		messageResponse := convertProtocolMessageToJSON(&result.Data.Message)

		// Convert addresses to hex strings
		var ccvAddresses []string
		if result.Data.MessageCCVAddresses != nil {
			ccvAddresses = make([]string, len(result.Data.MessageCCVAddresses))
			for i, addr := range result.Data.MessageCCVAddresses {
				ccvAddresses[i] = "0x" + hex.EncodeToString(addr)
			}
		}

		var executorAddress *string
		if result.Data.MessageExecutorAddress != nil {
			execAddr := "0x" + hex.EncodeToString(result.Data.MessageExecutorAddress)
			executorAddress = &execAddr
		}

		jsonResults = append(jsonResults, VerifierResultResponse{
			Message:                messageResponse,
			MessageCcvAddresses:    ccvAddresses,
			MessageExecutorAddress: executorAddress,
			CcvData:                "0x" + hex.EncodeToString(result.Data.CCVData),
			Metadata:               nil,
		})
	}

	response := VerifierResultsResponse{
		Results: jsonResults,
	}

	if len(errors) > 0 {
		response.Errors = errors
	}

	c.JSON(http.StatusOK, response)
}

// convertProtocolMessageToJSON converts a protocol.Message to MessageResponse.
func convertProtocolMessageToJSON(m *protocol.Message) *MessageResponse {
	var tokenTransferHex *string
	if m.TokenTransfer != nil {
		tokenTransferBytes := m.TokenTransfer.Encode()
		hexStr := "0x" + hex.EncodeToString(tokenTransferBytes)
		tokenTransferHex = &hexStr
	}

	return &MessageResponse{
		Version:             m.Version,
		SourceChainSelector: uint64(m.SourceChainSelector),
		DestChainSelector:   uint64(m.DestChainSelector),
		SequenceNumber:      uint64(m.SequenceNumber),
		OnRampAddress:       "0x" + hex.EncodeToString(m.OnRampAddress),
		OffRampAddress:      "0x" + hex.EncodeToString(m.OffRampAddress),
		Finality:            m.Finality,
		ExecutionGasLimit:   m.ExecutionGasLimit,
		CcipReceiveGasLimit: m.CcipReceiveGasLimit,
		CcvAndExecutorHash:  "0x" + hex.EncodeToString(m.CcvAndExecutorHash[:]),
		Sender:              "0x" + hex.EncodeToString(m.Sender),
		Receiver:            "0x" + hex.EncodeToString(m.Receiver),
		DestBlob:            "0x" + hex.EncodeToString(m.DestBlob),
		TokenTransfer:       tokenTransferHex,
		Data:                "0x" + hex.EncodeToString(m.Data),
	}
}
