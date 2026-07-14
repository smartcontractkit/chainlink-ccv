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

func TestRunnerPreparedReplacementKeepsOldJobReadyUntilCutover(t *testing.T) {
	var ready atomic.Bool
	var starts []string
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{startFn: func(_ context.Context, spec any, _ ServiceDeps) error {
			starts = append(starts, spec.(JobSpec).Name)
			return nil
		}},
		applicationReady: &ready,
	}

	oldSpec := "name = \"old\"\nappConfig = \"\""
	newSpec := "name = \"new\"\nappConfig = \"\""
	require.NoError(t, runner.StartJob(t.Context(), oldSpec))
	require.True(t, ready.Load())
	require.Equal(t, []string{"old"}, starts)

	require.NoError(t, runner.PrepareJob(t.Context(), newSpec))
	require.True(t, ready.Load(), "preparation must not make the active job unready")
	require.Equal(t, []string{"old"}, starts, "preparation must not activate the candidate")

	require.NoError(t, runner.StopJob(t.Context()))
	require.False(t, ready.Load())
	require.NoError(t, runner.StartJob(t.Context(), newSpec))
	require.True(t, ready.Load())
	require.Equal(t, []string{"old", "new"}, starts)
	require.NoError(t, runner.StopJob(t.Context()))
}

func TestRunnerPrepareJobSupersedesPreviousCandidate(t *testing.T) {
	var starts []string
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{startFn: func(_ context.Context, spec any, _ ServiceDeps) error {
			starts = append(starts, spec.(JobSpec).Name)
			return nil
		}},
	}

	require.NoError(t, runner.PrepareJob(t.Context(), "name = \"first\"\nappConfig = \"\""))
	first := runner.prepared
	require.NotNil(t, first)

	// A second PrepareJob without an intervening StartJob must discard the first candidate and
	// install the second, leaving exactly one prepared candidate.
	require.NoError(t, runner.PrepareJob(t.Context(), "name = \"second\"\nappConfig = \"\""))
	require.NotNil(t, runner.prepared)
	require.NotSame(t, first, runner.prepared)
	require.Equal(t, "second", runner.prepared.spec.Name)

	require.NoError(t, runner.StartJob(t.Context(), "name = \"second\"\nappConfig = \"\""))
	require.Equal(t, []string{"second"}, starts)
	require.NoError(t, runner.StopJob(t.Context()))
}

func TestRunnerStartJobDiscardsStalePreparedCandidate(t *testing.T) {
	var starts []string
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{startFn: func(_ context.Context, spec any, _ ServiceDeps) error {
			starts = append(starts, spec.(JobSpec).Name)
			return nil
		}},
	}

	require.NoError(t, runner.PrepareJob(t.Context(), "name = \"prepared\"\nappConfig = \"\""))
	require.NotNil(t, runner.prepared)

	// StartJob with a spec that does not match the prepared candidate must discard the stale
	// candidate and build the job actually requested by StartJob.
	require.NoError(t, runner.StartJob(t.Context(), "name = \"actual\"\nappConfig = \"\""))
	require.Equal(t, []string{"actual"}, starts)
	require.Nil(t, runner.prepared)

	require.NoError(t, runner.StopJob(t.Context()))
}

func TestRunnerPrepareFailureDoesNotChangeActiveJobReadiness(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	runner := &runner{
		lggr:             logger.Test(t),
		fac:              &spyServiceFactory{},
		applicationReady: &ready,
	}

	err := runner.PrepareJob(t.Context(), "not valid = [")
	require.Error(t, err)
	require.True(t, ready.Load())
	require.Nil(t, runner.prepared)
}

func TestRunnerDiscardPreparedJobIsIdempotent(t *testing.T) {
	runner := &runner{lggr: logger.Test(t), fac: &spyServiceFactory{}}
	require.NoError(t, runner.PrepareJob(t.Context(), "name = \"new\"\nappConfig = \"\""))
	require.NotNil(t, runner.prepared)
	require.NoError(t, runner.DiscardPreparedJob(t.Context()))
	require.Nil(t, runner.prepared)
	require.NoError(t, runner.DiscardPreparedJob(t.Context()))
}
