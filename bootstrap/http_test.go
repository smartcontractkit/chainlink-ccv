package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestInfoServerApplicationReadiness(t *testing.T) {
	var ready atomic.Bool
	server := newInfoServer(logger.Test(t), nil, 0, &ready)

	recorder := httptest.NewRecorder()
	server.handleApplicationReady(recorder, httptest.NewRequest(http.MethodGet, ApplicationReadyEndpoint, nil))
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.JSONEq(t, `{"status":"not_ready"}`, recorder.Body.String())

	ready.Store(true)
	recorder = httptest.NewRecorder()
	server.handleApplicationReady(recorder, httptest.NewRequest(http.MethodGet, ApplicationReadyEndpoint, nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"status":"ready"}`, recorder.Body.String())
}

func TestInfoServerHealthDoesNotRequireApplicationReadiness(t *testing.T) {
	var ready atomic.Bool
	server := newInfoServer(logger.Test(t), nil, 0, &ready)

	recorder := httptest.NewRecorder()
	server.handleHealth(recorder, httptest.NewRequest(http.MethodGet, HealthEndpoint, nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"status":"ok"}`, recorder.Body.String())
}

func TestRunnerApplicationReadinessTracksJobLifecycle(t *testing.T) {
	var ready atomic.Bool
	factory := &spyServiceFactory{
		startFn: func(context.Context, any, ServiceDeps) error {
			require.False(t, ready.Load(), "readiness must reset before a replacement job starts")
			return nil
		},
	}
	runner := &runner{
		lggr:             logger.Test(t),
		fac:              factory,
		applicationReady: &ready,
	}

	ready.Store(true)
	require.NoError(t, runner.StartJob(t.Context(), "name = \"test\"\nappConfig = \"\""))
	require.True(t, ready.Load())

	require.NoError(t, runner.StopJob(t.Context()))
	require.False(t, ready.Load())
}

func TestRunnerApplicationReadinessStaysFalseWhenJobStartFails(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{startFn: func(context.Context, any, ServiceDeps) error {
			return errors.New("start failed")
		}},
		applicationReady: &ready,
	}

	err := runner.StartJob(t.Context(), "name = \"test\"\nappConfig = \"\"")
	require.ErrorContains(t, err, "start failed")
	require.False(t, ready.Load())
}
