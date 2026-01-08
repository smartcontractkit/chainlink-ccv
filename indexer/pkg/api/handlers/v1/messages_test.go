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
		name       string
		query      string
		mockData   []common.MessageWithMetadata
		mockErr    error
		wantStatus int
		wantCount  int
	}{
		{name: "bad selectors", query: "sourceChainSelectors=not-a-number", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "bad dest selectors", query: "destChainSelectors=not-a-number", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "storage error", query: "", mockData: nil, mockErr: errors.New("db fail"), wantStatus: http.StatusInternalServerError},
		{name: "success", query: "", mockData: []common.MessageWithMetadata{msg}, mockErr: nil, wantStatus: http.StatusOK, wantCount: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ms := mocks.NewMockIndexerStorage(t)
			mm := mocks.NewMockIndexerMonitoring(t)
			mm.On("Metrics").Return(mocks.NewMockIndexerMetricLabeler(t)).Maybe()

			// Expect QueryMessages only when handler is expected to reach storage (not on bad selector parsing)
			if tc.wantStatus != http.StatusBadRequest {
				// QueryMessages(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
				ms.On("QueryMessages", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.mockData, tc.mockErr)
			}

			h := v1.NewMessagesHandler(ms, lggr, mm)
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
		})
	}
}
