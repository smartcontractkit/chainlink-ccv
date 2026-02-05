package lombard

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	lombardclient "github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

type RegisterAttestationRequest struct {
	MessageHash string `json:"messageHash" binding:"required"`
	Attestation string `json:"attestation" binding:"required"`
	Status      string `json:"status"      binding:"required"`
}

type AttestationAPI struct {
	mu        sync.RWMutex
	responses map[string]lombardclient.AttestationResponse
}

func NewAttestationAPI() *AttestationAPI {
	return &AttestationAPI{
		responses: make(map[string]lombardclient.AttestationResponse),
	}
}

// RegisterAttestation registers a new attestation response for a given message hash.
func (a *AttestationAPI) RegisterAttestation(messageHash, attestation, status string) lombardclient.AttestationResponse {
	a.mu.Lock()
	defer a.mu.Unlock()

	response := lombardclient.AttestationResponse{
		MessageHash: messageHash,
		Status:      lombardclient.AttestationStatus(status),
		Data:        attestation,
	}

	a.responses[messageHash] = response
	return response
}

func (a *AttestationAPI) Register() error {
	// POST endpoint to register attestation responses
	err := fake.Func("POST", "/lombard/v1/attestations", func(ctx *gin.Context) {
		var req RegisterAttestationRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response := a.RegisterAttestation(req.MessageHash, req.Attestation, req.Status)
		ctx.JSON(http.StatusOK, response)
	})
	if err != nil {
		return err
	}

	// POST endpoint to retrieve attestations by message hashes (batch request)
	err = fake.Func("POST", "/lombard/bridge/v1/deposits/getByHash", func(ctx *gin.Context) {
		var batchReq lombardclient.BatchRequest
		if err := ctx.ShouldBindJSON(&batchReq); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		a.mu.RLock()
		defer a.mu.RUnlock()

		attestations := make([]lombardclient.AttestationResponse, 0, len(batchReq.PayloadHashes))
		for _, messageHash := range batchReq.PayloadHashes {
			if response, exists := a.responses[messageHash]; exists {
				attestations = append(attestations, response)
			}
		}

		// Return wrapped in BatchResponse format
		batchResponse := lombardclient.BatchResponse{
			Attestations: attestations,
			Code:         0,
			Message:      "",
		}

		responseBytes, err := json.Marshal(batchResponse)
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
