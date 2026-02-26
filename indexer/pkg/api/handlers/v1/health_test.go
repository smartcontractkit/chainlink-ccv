package v1_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	ms := mocks.NewMockIndexerStorage(t)
	h := v1.NewHealthHandler(ms, lggr, mon)

	r := gin.New()
	r.GET("/health", h.Handle)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestReadyEndpoint_DBHealthy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	ms := mocks.NewMockIndexerStorage(t)
	ms.On("QueryMessages", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]common.MessageWithMetadata{}, nil)

	h := v1.NewHealthHandler(ms, lggr, mon)

	r := gin.New()
	r.GET("/ready", h.HandleReady)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestReadyEndpoint_DBDown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	ms := mocks.NewMockIndexerStorage(t)
	ms.On("QueryMessages", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, assert.AnError)
	h := v1.NewHealthHandler(ms, lggr, mon)

	r := gin.New()
	r.GET("/ready", h.HandleReady)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}
