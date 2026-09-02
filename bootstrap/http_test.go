package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
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

// createInfoServerKeystore builds an in-memory keystore holding an ECDSA_S256 key and returns it
// with the derived checksummed address, so tests can assert the endpoint's answer independently.
func createInfoServerKeystore(t *testing.T, keyName string) (keystore.Keystore, string) {
	t.Helper()

	ks, err := keystore.LoadKeystore(t.Context(), keystore.NewMemoryStorage(), "test-password")
	require.NoError(t, err)

	createResp, err := ks.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{{KeyName: keyName, KeyType: keystore.ECDSA_S256}},
	})
	require.NoError(t, err)
	require.Len(t, createResp.Keys, 1)

	pubKey, err := crypto.UnmarshalPubkey(createResp.Keys[0].KeyInfo.PublicKey)
	require.NoError(t, err)
	return ks, crypto.PubkeyToAddress(*pubKey).Hex()
}

func TestInfoServerGetKeyAddresses(t *testing.T) {
	const keyName = "test-ecdsa-key"
	ks, wantAddress := createInfoServerKeystore(t, keyName)
	server := newInfoServer(logger.Test(t), ks, 0, new(atomic.Bool))

	body, err := json.Marshal(keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	server.handleGetKeyAddresses(recorder, httptest.NewRequest(http.MethodPost, GetKeyAddressesEndpoint, bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, recorder.Code)

	var got map[string]string
	require.JSONEq(t, `{"`+keyName+`":"`+wantAddress+`"}`, recorder.Body.String())
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	require.Equal(t, wantAddress, got[keyName])
}

func TestInfoServerGetKeyAddressesRejectsMalformedRequest(t *testing.T) {
	server := newInfoServer(logger.Test(t), nil, 0, new(atomic.Bool))

	recorder := httptest.NewRecorder()
	server.handleGetKeyAddresses(recorder, httptest.NewRequest(http.MethodPost, GetKeyAddressesEndpoint, bytes.NewReader([]byte("not json"))))
	require.Equal(t, http.StatusBadRequest, recorder.Code)
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

func TestRunnerValidateJobKeepsActiveJobReady(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	started := false
	validated := false
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{
			validateFn: func(spec JobSpec) error {
				validated = true
				require.Equal(t, "replacement", spec.Name)
				return nil
			},
			startFn: func(context.Context, any, ServiceDeps) error {
				started = true
				return nil
			},
		},
		applicationReady: &ready,
	}

	require.NoError(t, runner.ValidateJob(t.Context(), "name = \"replacement\"\nappConfig = \"\""))
	require.True(t, validated)
	require.False(t, started, "validation must not start the replacement")
	require.True(t, ready.Load(), "validation must not change active-job readiness")
}

func TestRunnerValidateJob(t *testing.T) {
	t.Run("outer job spec", func(t *testing.T) {
		runner := &runner{lggr: logger.Test(t), fac: &spyServiceFactory{}}
		err := runner.ValidateJob(t.Context(), "not valid = [")
		require.ErrorContains(t, err, "failed to parse config")
	})

	t.Run("application config", func(t *testing.T) {
		wantErr := errors.New("invalid app config")
		runner := &runner{
			lggr: logger.Test(t),
			fac: &spyServiceFactory{validateFn: func(JobSpec) error {
				return wantErr
			}},
		}

		err := runner.ValidateJob(t.Context(), "name = \"replacement\"\nappConfig = \"\"")
		require.ErrorIs(t, err, wantErr)
		require.ErrorContains(t, err, "validate application config")
	})

	t.Run("chain config", func(t *testing.T) {
		runner := &runner{
			lggr: logger.Test(t),
			fac: &spyServiceFactory{validateFn: func(JobSpec) error {
				t.Error("factory validation must not run when the chain config does not decode")
				return nil
			}},
		}

		// The app config is TOML the registry decode in StartJob would reject.
		err := runner.ValidateJob(t.Context(), "name = \"replacement\"\nappConfig = \"not valid = [\"")
		require.ErrorContains(t, err, "validate chain config")
	})

	t.Run("allows blockchain infos without factory validator", func(t *testing.T) {
		runner := &runner{lggr: logger.Test(t), fac: &mockServiceFactory{}}
		const config = `name = "replacement"
appConfig = """
[blockchain_infos.5009297550715157269]
chain_id = "1"
"""`

		require.NoError(t, runner.ValidateJob(t.Context(), config))
	})
}

func TestRunnerStartJobFailureStopsFactory(t *testing.T) {
	stopCalls := 0
	runner := &runner{
		lggr: logger.Test(t),
		fac: &spyServiceFactory{
			startFn: func(context.Context, any, ServiceDeps) error {
				return errors.New("start failed")
			},
			stopFn: func(context.Context) error {
				stopCalls++
				return nil
			},
		},
	}

	err := runner.StartJob(t.Context(), "name = \"test\"\nappConfig = \"\"")
	require.ErrorContains(t, err, "start failed")
	require.Equal(t, 1, stopCalls, "a failed start must stop the factory so a retry cannot overwrite running components")
}
