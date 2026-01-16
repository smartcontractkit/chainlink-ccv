package cctp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

type AttestationResponse struct {
	Message        string         `json:"message"`
	EventNonce     string         `json:"eventNonce"`
	Attestation    string         `json:"attestation"`
	DecodedMessage DecodedMessage `json:"decodedMessage"`
	CCTPVersion    string         `json:"cctpVersion"`
	Status         string         `json:"status"`
}

type DecodedMessage struct {
	SourceDomain       string             `json:"sourceDomain"`
	DestinationDomain  string             `json:"destinationDomain"`
	Nonce              string             `json:"nonce"`
	Sender             string             `json:"sender"`
	Recipient          string             `json:"recipient"`
	DestinationCaller  string             `json:"destinationCaller"`
	MessageBody        string             `json:"messageBody"`
	DecodedMessageBody DecodedMessageBody `json:"decodedMessageBody"`
}

type DecodedMessageBody struct {
	BurnToken     string `json:"burnToken"`
	MintRecipient string `json:"mintRecipient"`
	Amount        string `json:"amount"`
	MessageSender string `json:"messageSender"`
	HookData      string `json:"hookData"`
}

type RegisterAttestationRequest struct {
	SourceDomain string `json:"sourceDomain" binding:"required"`
	MessageID    string `json:"messageID"    binding:"required"`
	Status       string `json:"status"       binding:"required"`
}

type AttestationAPI struct {
	mu        sync.RWMutex
	responses map[string]AttestationResponse
}

func NewAttestationAPI() *AttestationAPI {
	return &AttestationAPI{
		responses: make(map[string]AttestationResponse),
	}
}

// RegisterAttestation registers a new attestation response for a given sourceDomain.
func (a *AttestationAPI) RegisterAttestation(sourceDomain, messageID, status string) AttestationResponse {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Construct hookData as 0x8e1d1a9d + messageID (without 0x prefix)
	// Strip 0x prefix from messageID if present
	cleanMessageID := messageID
	if len(messageID) > 2 && messageID[:2] == "0x" {
		cleanMessageID = messageID[2:]
	}
	hookData := "0x8e1d1a9d" + cleanMessageID

	// Create a response based on the example attestation but with the provided sourceDomain, hookData and status
	response := AttestationResponse{
		Message:     "0xbbbbbb22",
		EventNonce:  "9682",
		Attestation: "0xaaaaaa11",
		DecodedMessage: DecodedMessage{
			SourceDomain:      sourceDomain,
			DestinationDomain: "5",
			Nonce:             "569",
			Sender:            "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
			Recipient:         "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
			DestinationCaller: "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
			MessageBody:       "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
			DecodedMessageBody: DecodedMessageBody{
				BurnToken:     "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
				MintRecipient: "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
				Amount:        "5000",
				MessageSender: "0x2609ac236def92d0992ff8bbcf810a59a9301bca",
				HookData:      hookData,
			},
		},
		CCTPVersion: "2",
		Status:      status,
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

		response := a.RegisterAttestation(req.SourceDomain, req.MessageID, req.Status)
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
		wrappedResponse := map[string][]AttestationResponse{
			"messages": {response},
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
