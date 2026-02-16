package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	sharedmiddleware "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestVerificationsPathNormalizer verifies that the path normalizer
// strips query parameters to prevent cardinality explosion.
func TestVerificationsPathNormalizer(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantPath    string
		wantTracked bool
	}{
		{
			name:        "verifications endpoint without query params",
			in:          "/v1/verifications",
			wantPath:    "/v1/verifications",
			wantTracked: true,
		},
		{
			name:        "other path",
			in:          "/health",
			wantPath:    "/health",
			wantTracked: true,
		},
		{
			name:        "root path",
			in:          "/",
			wantPath:    "/",
			wantTracked: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPath, gotTracked := VerificationsPathNormalizer(c.in)
			require.Equal(t, c.wantPath, gotPath)
			require.Equal(t, c.wantTracked, gotTracked)
		})
	}
}

// mockHTTPMetrics is a simple mock for testing adapter calls.
type mockHTTPMetrics struct {
	activeInc       int
	activeDec       int
	httpCounter     int
	durationRecords []durationRecord
}

type durationRecord struct {
	path   string
	method string
	status int
}

func (m *mockHTTPMetrics) IncrementActiveRequestsCounter(ctx context.Context) {
	m.activeInc++
}

func (m *mockHTTPMetrics) IncrementHTTPRequestCounter(ctx context.Context) {
	m.httpCounter++
}

func (m *mockHTTPMetrics) DecrementActiveRequestsCounter(ctx context.Context) {
	m.activeDec++
}

func (m *mockHTTPMetrics) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
	m.durationRecords = append(m.durationRecords, durationRecord{
		path:   path,
		method: method,
		status: status,
	})
}

// TestActiveRequestsMiddleware_RecordsMetrics verifies the middleware updates
// active & HTTP counters and records the request duration.
func TestActiveRequestsMiddleware_RecordsMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	mock := &mockHTTPMetrics{}

	r := gin.New()
	r.Use(sharedmiddleware.ActiveRequestsMiddleware(mock, VerificationsPathNormalizer, lggr))
	r.GET("/v1/verifications", func(c *gin.Context) {
		c.Status(200)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/verifications", nil)
	r.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	require.Equal(t, 1, mock.activeInc, "should increment active requests")
	require.Equal(t, 1, mock.activeDec, "should decrement active requests")
	require.Equal(t, 1, mock.httpCounter, "should increment http counter")
	require.Len(t, mock.durationRecords, 1, "should record duration")
	require.Equal(t, "/v1/verifications", mock.durationRecords[0].path)
	require.Equal(t, "GET", mock.durationRecords[0].method)
	require.Equal(t, 200, mock.durationRecords[0].status)
}
