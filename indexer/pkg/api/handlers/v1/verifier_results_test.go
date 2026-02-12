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

// TestVerifierResultsHandler_Handle covers invalid selector params, storage error,
// and successful responses for the /v1/verifierresults endpoint.
func TestVerifierResultsHandler_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	// sample ccv data map
	sampleMap := map[string][]common.VerifierResultWithMetadata{
		"0x1": {{VerifierResult: protocol.VerifierResult{}, Metadata: common.VerifierResultMetadata{VerifierName: "v1"}}},
	}

	cases := []struct {
		name             string
		query            string
		mockData         map[string][]common.VerifierResultWithMetadata
		mockErr          error
		wantStatus       int
		wantCount        int
		wantBodyContains []string
	}{
		{name: "bad selectors", query: "sourceChainSelectors=bad", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "bad dest selectors", query: "destChainSelectors=bad", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest},
		{name: "limit exceeds max returns 400 and storage not called", query: "limit=5000", mockData: nil, mockErr: nil, wantStatus: http.StatusBadRequest, wantBodyContains: []string{"limit exceeds maximum", "1000"}},
		{name: "storage error", query: "", mockData: nil, mockErr: errors.New("db fail"), wantStatus: http.StatusInternalServerError},
		{name: "success", query: "", mockData: sampleMap, mockErr: nil, wantStatus: http.StatusOK, wantCount: 1},
		{name: "limit equals max accepted and storage called with limit 1000", query: "limit=1000", mockData: sampleMap, mockErr: nil, wantStatus: http.StatusOK, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := mocks.NewMockIndexerStorage(t)
			mm := mocks.NewMockIndexerMonitoring(t)
			mm.On("Metrics").Return(mocks.NewMockIndexerMetricLabeler(t)).Maybe()

			reachesStorage := tc.wantStatus != http.StatusBadRequest
			if reachesStorage {
				// QueryCCVData(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
				ms.On("QueryCCVData", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.mockData, tc.mockErr)
			}

			h := v1.NewVerifierResultsHandler(ms, lggr, mm, v1.MaxQueryLimit)
			r := gin.New()
			r.GET("/verifierresults", h.Handle)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/verifierresults?"+tc.query, nil)
			r.ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantStatus == http.StatusOK {
				var resp v1.VerifierResultsResponse
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)
				require.Equal(t, tc.wantCount, len(resp.VerifierResults))
			}
			body := rec.Body.String()
			for _, sub := range tc.wantBodyContains {
				require.Contains(t, body, sub)
			}
		})
	}
}
