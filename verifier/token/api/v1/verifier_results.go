package v1

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
	MessageExecutorAddress string           `json:"message_executor_address,omitempty"`
	CcvData                string           `json:"ccv_data"`
	Metadata               *Metadata        `json:"metadata,omitempty"`
}

// MessageResponse represents a protocol.Message in JSON format.
type MessageResponse struct {
	Version             uint8  `json:"version"`
	SourceChainSelector uint64 `json:"source_chain_selector"`
	DestChainSelector   uint64 `json:"dest_chain_selector"`
	SequenceNumber      uint64 `json:"sequence_number"`
	OnRampAddress       string `json:"on_ramp_address"`
	OffRampAddress      string `json:"off_ramp_address"`
	Finality            uint16 `json:"finality"`
	ExecutionGasLimit   uint32 `json:"execution_gas_limit"`
	CcipReceiveGasLimit uint32 `json:"ccip_receive_gas_limit"`
	CcvAndExecutorHash  string `json:"ccv_and_executor_hash"`
	Sender              string `json:"sender"`
	Receiver            string `json:"receiver"`
	DestBlob            string `json:"dest_blob"`
	TokenTransfer       string `json:"token_transfer"`
	Data                string `json:"data"`
}

// Metadata placeholder for future use.
type Metadata struct {
	Timestamp             int64  `json:"timestamp,omitempty"`
	VerifierSourceAddress string `json:"verifier_source_address,omitempty"`
	VerifierDestAddress   string `json:"verifier_dest_address,omitempty"`
}

// VerifierResultsHandler handles HTTP requests for verifier results.
type VerifierResultsHandler struct {
	lggr                  logger.Logger
	storage               protocol.VerifierResultsAPI
	maxMessageIDsPerBatch int
}

func NewVerifierResultsHandler(
	lggr logger.Logger,
	storage protocol.VerifierResultsAPI,
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
			"error": fmt.Sprintf(
				"too many message_ids: %d, maximum allowed: %d",
				len(messageIDStrings),
				h.maxMessageIDsPerBatch),
		})
		return
	}

	messageIDs := make([]protocol.Bytes32, 0, len(messageIDStrings))
	for _, msgIDStr := range messageIDStrings {
		msgID, err := protocol.NewBytes32FromString(strings.TrimSpace(msgIDStr))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid message_id format: %s - %v", msgIDStr, err),
			})
			return
		}
		messageIDs = append(messageIDs, msgID)
	}

	results, err := h.storage.GetVerifications(c.Request.Context(), messageIDs)
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
			errors = append(errors, "message not found: "+messageID.String())
			continue
		}

		messageResponse := convertProtocolMessageToJSON(&result.Message)
		var ccvAddresses []string
		if result.MessageCCVAddresses != nil {
			ccvAddresses = make([]string, len(result.MessageCCVAddresses))
			for i, addr := range result.MessageCCVAddresses {
				ccvAddresses[i] = addr.String()
			}
		}

		var executorAddress string
		if result.MessageExecutorAddress != nil {
			executorAddress = result.MessageExecutorAddress.String()
		}

		jsonResults = append(jsonResults, VerifierResultResponse{
			Message:                messageResponse,
			MessageCcvAddresses:    ccvAddresses,
			MessageExecutorAddress: executorAddress,
			CcvData:                result.CCVData.String(),
			Metadata: &Metadata{
				Timestamp:             result.Timestamp.Unix(),
				VerifierSourceAddress: result.VerifierSourceAddress.String(),
				VerifierDestAddress:   result.VerifierDestAddress.String(),
			},
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
	var tokenTransferHex string

	if m.TokenTransfer != nil {
		tokenTransferBytes := m.TokenTransfer.Encode()
		tokenTransferHex = protocol.ByteSlice(tokenTransferBytes).String()
	}

	return &MessageResponse{
		Version:             m.Version,
		SourceChainSelector: uint64(m.SourceChainSelector),
		DestChainSelector:   uint64(m.DestChainSelector),
		SequenceNumber:      uint64(m.SequenceNumber),
		OnRampAddress:       m.OnRampAddress.String(),
		OffRampAddress:      m.OffRampAddress.String(),
		Finality:            m.Finality,
		ExecutionGasLimit:   m.ExecutionGasLimit,
		CcipReceiveGasLimit: m.CcipReceiveGasLimit,
		CcvAndExecutorHash:  m.CcvAndExecutorHash.String(),
		Sender:              m.Sender.String(),
		Receiver:            m.Receiver.String(),
		DestBlob:            m.DestBlob.String(),
		TokenTransfer:       tokenTransferHex,
		Data:                m.Data.String(),
	}
}
