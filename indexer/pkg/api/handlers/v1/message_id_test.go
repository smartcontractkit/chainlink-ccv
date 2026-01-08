package v1_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func makeHex64() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return "0x" + hex.EncodeToString(b)
}

// TestVerifierResultsByMessageID_Handle exercises handler responses for
// invalid, not found, error, and success cases using table-driven tests.
func TestVerifierResultsByMessageID_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	validMsgID := makeHex64()
	bytes32, err := protocol.NewBytes32FromString(validMsgID)
	require.NoError(t, err)

	// prepare a sample verification payload
	sample := common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{MessageID: bytes32},
		Metadata:       common.VerifierResultMetadata{VerifierName: "v1"},
	}

	cases := []struct {
		name           string
		messageID      string
		mockData       []common.VerifierResultWithMetadata
		mockErr        error
		wantStatus     int
		wantResultsLen int
	}{}

	cases = append(cases, []struct {
		name           string
		messageID      string
		mockData       []common.VerifierResultWithMetadata
		mockErr        error
		wantStatus     int
		wantResultsLen int
	}{
		{name: "invalid id", messageID: "not-a-hex", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "not found", messageID: validMsgID, mockData: nil, mockErr: storage.ErrCCVDataNotFound, wantStatus: http.StatusNotFound},
		{name: "storage error", messageID: validMsgID, mockData: nil, mockErr: errors.New("db fail"), wantStatus: http.StatusInternalServerError},
		{name: "success", messageID: validMsgID, mockData: []common.VerifierResultWithMetadata{sample}, mockErr: nil, wantStatus: http.StatusOK, wantResultsLen: 1},
	}...)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// create mocks
			ms := mocks.NewMockIndexerStorage(t)
			mm := mocks.NewMockIndexerMonitoring(t)
			mm.On("Metrics").Return(mocks.NewMockIndexerMetricLabeler(t)).Maybe()

			// If the ID is valid, expect GetCCVData to be called with the parsed Bytes32
			if tc.messageID != "not-a-hex" {
				mID, _ := protocol.NewBytes32FromString(tc.messageID)
				ms.On("GetCCVData", mock.Anything, mID).Return(tc.mockData, tc.mockErr)
			}

			h := v1.NewVerifierResultsByMessageIDHandler(ms, lggr, mm)
			r := gin.New()
			r.GET("/verifierresults/:messageID", h.Handle)

			req := httptest.NewRequest("GET", "/verifierresults/"+tc.messageID, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantStatus == http.StatusOK {
				var resp v1.VerifierResultsByMessageIDResponse
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)
				require.Equal(t, tc.wantResultsLen, len(resp.Results))
				require.Equal(t, bytes32, resp.MessageID)
			}
		})
	}
}
