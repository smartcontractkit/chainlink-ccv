package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestRemoveMessageIDFromPath ensures message IDs in verifierresults paths are
// normalized to a canonical placeholder so they don't leak into metrics/logs.
func TestRemoveMessageIDFromPath(t *testing.T) {
	cases := []struct {
		in          string
		wantPath    string
		wantTracked bool
	}{
		{"/verifierresults/0xabcde", "/verifierresults/:messageID", true},
		{"/verifierresults/0x1/foo", "/verifierresults/:messageID", true},
		{"/foo/bar", "/foo/bar", true},
	}
	for _, c := range cases {
		gotPath, gotTracked := RemoveMessageIDFromPath(c.in)
		require.Equal(t, c.wantPath, gotPath)
		require.Equal(t, c.wantTracked, gotTracked)
	}
}

// TestRateLimit_HandlerEnabledAndDisabled checks that the RateLimit middleware
// behaves as a no-op when disabled and allows requests when enabled (under the limit).
func TestRateLimit_HandlerEnabledAndDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	// Disabled case: middleware should be no-op and allow request through
	cfgOff := &config.Config{API: config.APIConfig{RateLimit: config.RateLimitConfig{Enabled: false}}}
	r := gin.New()
	r.Use(RateLimit(lggr, cfgOff))
	r.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Enabled case: should also allow a request under rate limit
	cfgOn := &config.Config{API: config.APIConfig{RateLimit: config.RateLimitConfig{Enabled: true}}}
	r2 := gin.New()
	r2.Use(RateLimit(lggr, cfgOn))
	r2.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	r2.ServeHTTP(rec2, req2)
	require.Equal(t, 200, rec2.Code)
}
