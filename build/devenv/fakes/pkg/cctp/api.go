package cctp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	cctpclient "github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

type RegisterAttestationRequest struct {
	SourceDomain  string `json:"sourceDomain"  binding:"required"`
	MessageID     string `json:"messageID"     binding:"required"`
	Status        string `json:"status"        binding:"required"`
	MessageSender string `json:"messageSender" binding:"required"`
	Message       string `json:"message"`
	Attestation   string `json:"attestation"`
}

type AttestationAPI struct {
	mu        sync.RWMutex
	responses map[string]cctpclient.Message
}

func NewAttestationAPI() *AttestationAPI {
	return &AttestationAPI{
		responses: make(map[string]cctpclient.Message),
	}
}

// RegisterAttestation registers a new attestation response for a given sourceDomain.
func (a *AttestationAPI) RegisterAttestation(sourceDomain, messageID, status, message, attestation, messageSender string) cctpclient.Message {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Construct hookData as 0x8e1d1a9d + messageID (without 0x prefix)
	// Strip 0x prefix from messageID if present
	cleanMessageID := messageID
	if len(messageID) > 2 && messageID[:2] == "0x" {
		cleanMessageID = messageID[2:]
	}
	hookData := "0x8e1d1a9d" + cleanMessageID

	// Use provided values or defaults
	if message == "" {
		message = "0xbbbbbbbb"
	}
	if attestation == "" {
		attestation = "0xaaaaaaaa"
	}

	// Create a response based on the example attestation but with the provided sourceDomain, hookData and status
	response := cctpclient.Message{
		Message:     message,
		EventNonce:  "9682",
		Attestation: attestation,
		DecodedMessage: cctpclient.DecodedMessage{
			SourceDomain:      sourceDomain,
			DestinationDomain: "5",
			Nonce:             "569",
			Sender:            "0xthis_is_ignored_for_simplicity",
			Recipient:         "0xthis_is_ignored_for_simplicity",
			DestinationCaller: "0xthis_is_ignored_for_simplicity",
			MessageBody:       "0xthis_is_ignored_for_simplicity",
			DecodedMessageBody: cctpclient.DecodedMessageBody{
				BurnToken:     "0xthis_is_ignored_for_simplicity",
				MintRecipient: "0xthis_is_ignored_for_simplicity",
				Amount:        "1000",
				MessageSender: messageSender,
				HookData:      hookData,
			},
		},
		CCTPVersion: "2",
		Status:      cctpclient.AttestationStatus(status),
	}

	a.responses[sourceDomain] = response
	return response
}

func (a *AttestationAPI) Register() error {
	// POST endpoint to register attestation responses
	err := fake.Func("POST", "/cctp/v2/attestations", func(ctx *gin.Context) {
		var req RegisterAttestationRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response := a.RegisterAttestation(req.SourceDomain, req.MessageID, req.Status, req.Message, req.Attestation, req.MessageSender)
		ctx.JSON(http.StatusOK, response)
	})
	if err != nil {
		return err
	}

	// GET endpoint to retrieve attestation by sourceDomain
	err = fake.Func("GET", "/cctp/v2/messages/:sourceDomain", func(ctx *gin.Context) {
		sourceDomain := ctx.Param("sourceDomain")

		a.mu.RLock()
		response, exists := a.responses[sourceDomain]
		a.mu.RUnlock()

		if !exists {
			ctx.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no attestation found for sourceDomain: %s", sourceDomain)})
			return
		}

		// Return wrapped in "messages" array to match the expected format
		wrappedResponse := cctpclient.Messages{
			Messages: []cctpclient.Message{response},
		}
		responseBytes, err := json.Marshal(wrappedResponse)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.Data(http.StatusOK, "application/json", responseBytes)
	})
	if err != nil {
		return err
	}

	return nil
}
