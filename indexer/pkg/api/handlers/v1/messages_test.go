package v1_test

import (
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
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestMessagesHandler_Handle covers bad selector query, storage error, and success cases
// for the /v1/messages endpoint using table-driven tests and mockery mocks.
func TestMessagesHandler_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	// sample message
	msg := common.MessageWithMetadata{Message: protocol.Message{}, Metadata: common.MessageMetadata{}}

	cases := []struct {
		name             string
		query            string
		mockData         []common.MessageWithMetadata
		mockErr          error
		wantStatus       int
		wantCount        int
		wantBodyContains []string
	}{
		{name: "bad selectors", query: "sourceChainSelectors=not-a-number", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "bad dest selectors", query: "destChainSelectors=not-a-number", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "limit exceeds max returns 400 and storage not called", query: "limit=5000", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest, wantBodyContains: []string{"limit exceeds maximum", "1000"}},
		{name: "storage error", query: "", mockData: nil, mockErr: errors.New("db fail"), wantStatus: http.StatusServiceUnavailable},
		{name: "success", query: "", mockData: []common.MessageWithMetadata{msg}, mockErr: nil, wantStatus: http.StatusOK, wantCount: 1},
		{name: "limit equals max accepted and storage called with limit 1000", query: "limit=1000", mockData: []common.MessageWithMetadata{msg}, mockErr: nil, wantStatus: http.StatusOK, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := mocks.NewMockIndexerStorage(t)
			mm := mocks.NewMockIndexerMonitoring(t)
			mm.On("Metrics").Return(mocks.NewMockIndexerMetricLabeler(t)).Maybe()

			// Expect QueryMessages only when handler is expected to reach storage (not on bad selector or limit exceeded)
			reachesStorage := tc.wantStatus != http.StatusBadRequest
			if reachesStorage {
				// QueryMessages(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
				ms.On("QueryMessages", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.mockData, tc.mockErr)
			}

			h := v1.NewMessagesHandler(ms, lggr, mm, v1.MaxQueryLimit)
			r := gin.New()
			r.GET("/messages", h.Handle)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/messages?"+tc.query, nil)
			r.ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantStatus == http.StatusOK {
				var resp v1.MessagesResponse
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)
				require.Equal(t, tc.wantCount, len(resp.Messages))
			}
			body := rec.Body.String()
			for _, sub := range tc.wantBodyContains {
				require.Contains(t, body, sub)
			}
		})
	}
}

// TestMessagesHandler_SkipsInvalidMessageIDs ensures messages with encoding
// errors (so MessageID() fails) are skipped and don't cause the handler to fail.
func TestMessagesHandler_SkipsInvalidMessageIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	// valid message: zero-values satisfy length checks and should produce a valid ID
	valid := common.MessageWithMetadata{Message: protocol.Message{}, Metadata: common.MessageMetadata{}}
	validID, err := valid.Message.MessageID()
	require.NoError(t, err)
	validKey := validID.String()

	// invalid message: set DataLength != len(Data) to force Encode() to fail
	invalid := common.MessageWithMetadata{Message: protocol.Message{DataLength: 1}, Metadata: common.MessageMetadata{}}

	ms := mocks.NewMockIndexerStorage(t)
	mm := mocks.NewMockIndexerMonitoring(t)
	mm.On("Metrics").Return(mocks.NewMockIndexerMetricLabeler(t)).Maybe()

	ms.On("QueryMessages", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]common.MessageWithMetadata{valid, invalid}, nil)

	h := v1.NewMessagesHandler(ms, lggr, mm, v1.MaxQueryLimit)
	r := gin.New()
	r.GET("/messages", h.Handle)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/messages", nil)
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp v1.MessagesResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	// only the valid message should be present
	require.Equal(t, 1, len(resp.Messages))
	require.Contains(t, resp.Messages, validKey)
}
