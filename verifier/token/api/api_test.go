package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/ccvstorage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestRateLimitingAppliedToVerificationsEndpoint(t *testing.T) {
	lggr := logger.Test(t)

	// Set up in-memory storage
	inmemoryStorage := ccvstorage.NewInMemory()
	ccvReader := storage.NewAttestationCCVReader(inmemoryStorage)

	// Set up fake monitoring
	mon := monitoring.NewFakeVerifierMonitoring()

	router := NewHTTPAPI(lggr, ccvReader, nil, mon)

	// Use a valid messageID format (64 hex chars with 0x prefix)
	validMessageID := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	// First 10 requests should succeed (default rate limit is 10 req/s per IP)
	for i := range 10 {
		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/v1/verifications?messageID="+validMessageID, nil)
		require.NoError(t, err)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i)
	}

	// 11th request should be rate limited
	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/verifications?messageID="+validMessageID, nil)
	require.NoError(t, err)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited after 10 requests")
}

func TestHealthEndpointsNotRateLimited(t *testing.T) {
	lggr := logger.Test(t)

	// Set up in-memory storage
	inmemoryStorage := ccvstorage.NewInMemory()
	ccvReader := storage.NewAttestationCCVReader(inmemoryStorage)

	// Set up fake monitoring
	mon := monitoring.NewFakeVerifierMonitoring()

	router := NewHTTPAPI(lggr, ccvReader, nil, mon)

	// Health endpoints should not be rate limited
	// Make 20 requests to verify no rate limiting
	for i := range 20 {
		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/health/live", nil)
		require.NoError(t, err)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Health request %d should succeed (no rate limiting)", i)
	}
}
