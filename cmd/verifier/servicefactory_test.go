package verifier

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

type callbackSourceReader struct {
	chainaccess.SourceReader
	callback func(context.Context)
}

func (r *callbackSourceReader) SetCriticalSourceInvariantCallback(callback func(context.Context)) {
	r.callback = callback
}

func TestInstrumentSourceReader(t *testing.T) {
	const selector = protocol.ChainSelector(5009297550715157269)
	ctx := context.Background()
	latest := &protocol.BlockHeader{Number: 101}
	finalized := &protocol.BlockHeader{Number: 99}
	delegate := mocks.NewMockSourceReader(t)
	delegate.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Once()
	configurableReader := &callbackSourceReader{SourceReader: delegate}
	verifierMonitoring := monitoring.NewFakeVerifierMonitoring()

	reader, err := instrumentSourceReader(configurableReader, "verifier-1", selector, verifierMonitoring)
	require.NoError(t, err)
	require.NotNil(t, configurableReader.callback)

	gotLatest, gotFinalized, err := reader.LatestAndFinalizedBlock(ctx)
	require.NoError(t, err)
	require.Equal(t, latest, gotLatest)
	require.Equal(t, finalized, gotFinalized)
	require.Equal(t, int64(101), verifierMonitoring.Fake.SourceChainLatestBLock.Load())
	require.Equal(t, int64(99), verifierMonitoring.Fake.SourceChainFinalizedBlock.Load())

	configurableReader.callback(ctx)
	require.Equal(t, int64(1), verifierMonitoring.Fake.CriticalSourceInvariantViolations.Load())
}

// TestFactoryValidate exercises the ServiceFactoryValidator implementation: the same
// decode+Validate checks Start performs, but with no secrets loading, DB connection,
// or services constructed.
func TestFactoryValidate(t *testing.T) {
	f, ok := NewCommitteeVerifierServiceFactory().(bootstrap.ServiceFactoryValidator)
	require.True(t, ok, "committee verifier factory must implement ServiceFactoryValidator")

	t.Run("valid config", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"

[committee_verifier_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000002"

[rmn_remote_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000003"
`
		require.NoError(t, f.Validate(bootstrap.JobSpec{AppConfig: appConfig}))
	})

	t.Run("invalid TOML", func(t *testing.T) {
		err := f.Validate(bootstrap.JobSpec{AppConfig: "not valid toml =="})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get app config")
	})

	t.Run("mismatched address maps", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mismatched lengths")
	})

	t.Run("both aggregator fields set", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[[aggregators]]
address = "localhost:50052"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aggregator_address is deprecated")
	})
}

func TestCommitteeFeatureValidator(t *testing.T) {
	validator := func(t *testing.T) bootstrap.FeatureValidator {
		t.Helper()
		v, ok := NewCommitteeVerifierServiceFactory().(bootstrap.FeatureValidator)
		require.True(t, ok, "committee verifier factory must implement FeatureValidator")
		return v
	}
	logPollerOn := bootstrap.Features{LogPoller: true}

	// isolate points the secrets file and the DB env var at known values for the test.
	isolate := func(t *testing.T, secretsPath, envURL string) {
		t.Helper()
		t.Setenv(vsecrets.CommitteeVerifierSecretsPathEnv, secretsPath)
		t.Setenv(vsecrets.DatabaseURLEnvVar, envURL)
	}
	writeSecrets := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "secrets.toml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	t.Run("flag off reads no secrets", func(t *testing.T) {
		// A directory cannot be decoded as a secrets file, so any read would fail.
		isolate(t, t.TempDir(), "")
		require.NoError(t, validator(t).ValidateFeatures(bootstrap.Features{}))
	})

	t.Run("flag on without a database URL names both settings", func(t *testing.T) {
		isolate(t, filepath.Join(t.TempDir(), "absent.toml"), "")
		err := validator(t).ValidateFeatures(logPollerOn)
		require.Error(t, err)
		require.Contains(t, err.Error(), "[db].url")
		require.Contains(t, err.Error(), vsecrets.DatabaseURLEnvVar)
	})

	t.Run("flag on with the URL in the secrets file", func(t *testing.T) {
		isolate(t, writeSecrets(t, "[db]\nurl = \"postgres://localhost:5432/verifier\"\n"), "")
		require.NoError(t, validator(t).ValidateFeatures(logPollerOn))
	})

	t.Run("flag on with the URL in the environment", func(t *testing.T) {
		isolate(t, filepath.Join(t.TempDir(), "absent.toml"), "postgres://localhost:5432/verifier")
		require.NoError(t, validator(t).ValidateFeatures(logPollerOn))
	})

	t.Run("flag on with a malformed secrets file", func(t *testing.T) {
		isolate(t, writeSecrets(t, "not valid toml =="), "")
		err := validator(t).ValidateFeatures(logPollerOn)
		require.ErrorContains(t, err, "failed to load verifier secrets")
	})
}

func TestTokenFeatureValidator(t *testing.T) {
	v, ok := NewTokenVerifierServiceFactory().(bootstrap.FeatureValidator)
	require.True(t, ok, "token verifier factory must implement FeatureValidator")

	t.Run("flag on is rejected", func(t *testing.T) {
		err := v.ValidateFeatures(bootstrap.Features{LogPoller: true})
		require.ErrorContains(t, err, "LogPoller source reader is not supported for the token verifier")
	})

	t.Run("flag off is accepted", func(t *testing.T) {
		require.NoError(t, v.ValidateFeatures(bootstrap.Features{}))
	})
}
