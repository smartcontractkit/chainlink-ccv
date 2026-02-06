package infoserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestServer_InfoEndpoint(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	signingAddr := "0x1234567890abcdef1234567890abcdef12345678"
	csaPubKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	server := New(":0", signingAddr, csaPubKey, lggr)

	// Test the handler directly using httptest
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	w := httptest.NewRecorder()
	server.handleInfo(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var infoResp InfoResponse
	err = json.Unmarshal(body, &infoResp)
	require.NoError(t, err)

	assert.Equal(t, signingAddr, infoResp.SigningAddress)
	assert.Equal(t, hex.EncodeToString(csaPubKey), infoResp.CSAPublicKey)
}

func TestServer_HealthEndpoint(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	server := New(":0", "0x1234", []byte{1, 2, 3}, lggr)

	// Test initial phase (READY)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var healthResp HealthResponse
	err = json.Unmarshal(body, &healthResp)
	require.NoError(t, err)

	assert.Equal(t, "ok", healthResp.Status)
	assert.Equal(t, string(PhaseReady), healthResp.Phase)

	// Change phase and verify
	server.SetPhase(PhaseActive)

	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	server.handleHealth(w, req)

	resp = w.Result()
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	err = json.Unmarshal(body, &healthResp)
	require.NoError(t, err)

	assert.Equal(t, string(PhaseActive), healthResp.Phase)
}

func TestServer_InfoEndpoint_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	server := New(":0", "0x1234", []byte{1, 2, 3}, lggr)

	// Test POST request (should be rejected)
	req := httptest.NewRequest(http.MethodPost, "/info", nil)
	w := httptest.NewRecorder()
	server.handleInfo(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestServer_PhaseTransitions(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	server := New(":0", "0x1234", []byte{1, 2, 3}, lggr)

	// Initial phase is READY
	assert.Equal(t, PhaseReady, server.GetPhase())

	// Transition to ACTIVE
	server.SetPhase(PhaseActive)
	assert.Equal(t, PhaseActive, server.GetPhase())

	// Can also set to INIT
	server.SetPhase(PhaseInit)
	assert.Equal(t, PhaseInit, server.GetPhase())
}

func TestServer_StartAndShutdown(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	server := New("127.0.0.1:0", "0x1234", []byte{1, 2, 3}, lggr)

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	require.NoError(t, err)

	// Check that Start returned http.ErrServerClosed
	select {
	case err := <-errCh:
		assert.Equal(t, http.ErrServerClosed, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Server didn't shut down in time")
	}
}
