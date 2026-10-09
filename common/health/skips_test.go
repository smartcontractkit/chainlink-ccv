package health

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartupSkips_NoSkipsIsReady(t *testing.T) {
	s := NewStartupSkips("svc.StartupSkips")

	assert.NoError(t, s.Ready())
	assert.Equal(t, "svc.StartupSkips", s.Name())

	svcHealth := CheckServiceHealth(s)
	assert.Equal(t, Ready, svcHealth.Status)
	response := NewReadinessResponse([]ServicesHealth{svcHealth})
	assert.Equal(t, http.StatusOK, response.StatusCode())
}

func TestStartupSkips_SkipFlipsReadinessToNotReady(t *testing.T) {
	s := NewStartupSkips("svc.StartupSkips")
	s.Skip("Verifier[bad]", errors.New("invalid issuer address"))
	s.Skip("DiscoverySource[0xdead]", errors.New("dial failed"))

	err := s.Ready()
	require.Error(t, err)
	assert.ErrorContains(t, err, "2 component(s) skipped at startup")
	assert.ErrorContains(t, err, "Verifier[bad]: invalid issuer address")
	assert.ErrorContains(t, err, "DiscoverySource[0xdead]: dial failed")

	report := s.HealthReport()
	assert.ErrorContains(t, report["svc.StartupSkips"], "skipped at startup")
	assert.ErrorContains(t, report["svc.StartupSkips[Verifier[bad]]"], "invalid issuer address")
	assert.ErrorContains(t, report["svc.StartupSkips[DiscoverySource[0xdead]]"], "dial failed")

	svcHealth := CheckServiceHealth(s)
	assert.Equal(t, NotReady, svcHealth.Status)
	response := NewReadinessResponse([]ServicesHealth{svcHealth})
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
}

func TestStartupSkips_NilErrorGetsDefaultMessage(t *testing.T) {
	s := NewStartupSkips("svc.StartupSkips")
	s.Skip("Verifier[bad]", nil)

	assert.ErrorContains(t, s.Ready(), "Verifier[bad]: skipped at startup")
}

func TestStartupSkips_SameComponentOverwrites(t *testing.T) {
	s := NewStartupSkips("svc.StartupSkips")
	s.Skip("Verifier[bad]", errors.New("first"))
	s.Skip("Verifier[bad]", errors.New("second"))

	assert.ErrorContains(t, s.Ready(), "1 component(s) skipped at startup")
	assert.ErrorContains(t, s.Ready(), "second")
	assert.NotContains(t, s.Ready().Error(), "first")
}
