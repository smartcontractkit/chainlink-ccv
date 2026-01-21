package v1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
)

func Test_VerifierResultsHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	inmemoryStorage := chainstatus.NewInMemory()
	ccvWriter := storage.NewAttestationCCVWriter(
		logger.Test(t),
		map[protocol.ChainSelector]protocol.UnknownAddress{
			1:  {0x01, 0x02, 0x03},
			2:  {0x04, 0x05, 0x06},
			10: {0x07, 0x08, 0x09},
			20: {0x0a, 0x0b, 0x0c},
		},
		inmemoryStorage,
	)
	ccvReader := storage.NewAttestationCCVReader(
		inmemoryStorage,
	)

	lggr := logger.Test(t)

	messageID1, verifierResult1 := createSampleMessage(1, 2, 10)
	messageID2, verifierResult2 := createSampleMessage(10, 20, 20)

	err := ccvWriter.WriteCCVNodeData(
		t.Context(),
		[]protocol.VerifierNodeResult{
			verifierResult1,
			verifierResult2,
		})
	require.NoError(t, err)

	handler := NewVerifierResultsHandler(lggr, ccvReader)

	t.Run("successful request - messageID prefixed with 0x", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		req, _ := http.NewRequest(
			"GET",
			"/verifications?messageID="+messageID1.String(),
			nil,
		)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response v1.VerifierResultsResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response.Results, 1)
		assert.NotNil(t, response.Results[0].Message)
		assert.Equal(t, uint64(1), response.Results[0].Message.SourceChainSelector)
		assert.Equal(t, uint64(2), response.Results[0].Message.DestChainSelector)
		assert.Equal(t, uint64(10), response.Results[0].Message.SequenceNumber)

		expectedJSON := `{
			"results": [{
				"message": {
					"version": 1,
					"source_chain_selector": 1,
					"dest_chain_selector": 2,
					"sequence_number": 10,
					"on_ramp_address": "0x010203",
					"on_ramp_address_length": 3,
					"off_ramp_address": "0x040506",
					"off_ramp_address_length": 3,
					"finality": 10,
					"execution_gas_limit": 200000,
					"ccip_receive_gas_limit": 150000,
					"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
					"sender": "0x070809",
					"sender_length": 3,
					"receiver": "0x0a0b0c",
					"receiver_length": 3,
					"dest_blob": "0x0d0e0f",
					"dest_blob_length": 3,
					"token_transfer": null,
					"token_transfer_length": 0,
					"data": "0x101112",
					"data_length": 3
				},
				"message_ccv_addresses": ["0x131415"],
				"message_executor_address": "0x161718",
				"ccv_data": "0x191a1b",
				"metadata": {
					"timestamp": ` + fmt.Sprint(response.Results[0].Metadata.Timestamp) + `,
					"verifier_source_address": "0x010203",
					"verifier_dest_address": "0x040506"
				}
			}]
		}`
		assert.JSONEq(t, expectedJSON, w.Body.String())
	})

	t.Run("bad request - raw messageID string", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		req, _ := http.NewRequest(
			"GET", "/verifications?messageID="+hex.EncodeToString(messageID2[:]),
			nil,
		)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing messageID parameter", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		req, _ := http.NewRequest("GET", "/verifications", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.JSONEq(t, `{"error":"messageID query parameter is required"}`, w.Body.String())
	})

	t.Run("invalid hex format", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		req, _ := http.NewRequest("GET", "/verifications?messageID=invalid_hex", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.JSONEq(t, `{"error":"invalid message_id format: invalid_hex - Bytes32 must start with '0x' prefix: invalid_hex"}`, w.Body.String())
	})

	t.Run("multiple message IDs", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		messageID1Hex := messageID1.String()
		messageID2Hex := messageID2.String()
		req, _ := http.NewRequest("GET", "/verifications?messageID="+messageID1Hex+","+messageID2Hex, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response v1.VerifierResultsResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response.Results, 2)
		assert.Equal(t, uint64(10), response.Results[0].Message.SequenceNumber)
		assert.Equal(t, uint64(20), response.Results[1].Message.SequenceNumber)

		expectedJSON := `{
			"results": [
				{
					"message": {
						"version": 1,
						"source_chain_selector": 1,
						"dest_chain_selector": 2,
						"sequence_number": 10,
						"on_ramp_address": "0x010203",
						"on_ramp_address_length": 3,
						"off_ramp_address": "0x040506",
						"off_ramp_address_length": 3,
						"finality": 10,
						"execution_gas_limit": 200000,
						"ccip_receive_gas_limit": 150000,
						"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
						"sender": "0x070809",
						"sender_length": 3,
						"receiver": "0x0a0b0c",
						"receiver_length": 3,
						"dest_blob": "0x0d0e0f",
						"dest_blob_length": 3,
						"token_transfer": null,
						"token_transfer_length": 0,
						"data": "0x101112",
						"data_length": 3
					},
					"message_ccv_addresses": ["0x131415"],
					"message_executor_address": "0x161718",
					"ccv_data": "0x191a1b",
					"metadata": {
						"timestamp": ` + fmt.Sprint(response.Results[0].Metadata.Timestamp) + `,
						"verifier_source_address": "0x010203",
						"verifier_dest_address": "0x040506"
					}
				},
				{
					"message": {
						"version": 1,
						"source_chain_selector": 10,
						"dest_chain_selector": 20,
						"sequence_number": 20,
						"on_ramp_address": "0x010203",
						"on_ramp_address_length": 3,
						"off_ramp_address": "0x040506",
						"off_ramp_address_length": 3,
						"finality": 10,
						"execution_gas_limit": 200000,
						"ccip_receive_gas_limit": 150000,
						"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
						"sender": "0x070809",
						"sender_length": 3,
						"receiver": "0x0a0b0c",
						"receiver_length": 3,
						"dest_blob": "0x0d0e0f",
						"dest_blob_length": 3,
						"token_transfer": null,
						"token_transfer_length": 0,
						"data": "0x101112",
						"data_length": 3
					},
					"message_ccv_addresses": ["0x131415"],
					"message_executor_address": "0x161718",
					"ccv_data": "0x191a1b",
					"metadata": {
						"timestamp": ` + fmt.Sprint(response.Results[1].Metadata.Timestamp) + `,
						"verifier_source_address": "0x070809",
						"verifier_dest_address": "0x0a0b0c"
					}
				}
			]
		}`
		assert.JSONEq(t, expectedJSON, w.Body.String())
	})

	t.Run("message not found", func(t *testing.T) {
		router := gin.New()
		router.GET("/verifications", handler.Handle)

		messageID, _ := createSampleMessage(100, 200, 200)
		messageIDHex := messageID.String()

		req, _ := http.NewRequest("GET", "/verifications?messageID="+messageIDHex, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response v1.VerifierResultsResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Len(t, response.Results, 0)
		assert.Len(t, response.Errors, 1)
		assert.Contains(t, response.Errors[0].Message, "message not found")

		expectedJSON := `{
			"results": [],
			"errors": ["message not found: ` + messageIDHex + `"]
		}`
		assert.JSONEq(t, expectedJSON, w.Body.String())
	})
}

func createSampleMessage(sourceChain, destChain, seqNum uint64) (protocol.Bytes32, protocol.VerifierNodeResult) {
	message := protocol.Message{
		Version:              1,
		SourceChainSelector:  protocol.ChainSelector(sourceChain),
		DestChainSelector:    protocol.ChainSelector(destChain),
		SequenceNumber:       protocol.SequenceNumber(seqNum),
		OnRampAddress:        []byte{0x01, 0x02, 0x03},
		OffRampAddress:       []byte{0x04, 0x05, 0x06},
		Finality:             10,
		ExecutionGasLimit:    200000,
		CcipReceiveGasLimit:  150000,
		CcvAndExecutorHash:   protocol.Bytes32{},
		Sender:               []byte{0x07, 0x08, 0x09},
		Receiver:             []byte{0x0a, 0x0b, 0x0c},
		DestBlob:             []byte{0x0d, 0x0e, 0x0f},
		Data:                 []byte{0x10, 0x11, 0x12},
		OnRampAddressLength:  3,
		OffRampAddressLength: 3,
		SenderLength:         3,
		ReceiverLength:       3,
		DestBlobLength:       3,
		DataLength:           3,
	}
	messageID := message.MustMessageID()
	verifierResult := protocol.VerifierNodeResult{
		MessageID:       messageID,
		Message:         message,
		CCVAddresses:    []protocol.UnknownAddress{{0x13, 0x14, 0x15}},
		ExecutorAddress: protocol.UnknownAddress{0x16, 0x17, 0x18},
		Signature:       []byte{0x19, 0x1a, 0x1b},
	}
	return messageID, verifierResult
}
