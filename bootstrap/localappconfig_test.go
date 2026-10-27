package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingMockFactory is a ServiceFactory that also implements
// ServiceFactoryValidator, recording the app configs it is handed.
type recordingMockFactory struct {
	appConfigs []string
	err        error
}

func (f *recordingMockFactory) Start(context.Context, JobSpec, ServiceDeps) error { return nil }
func (f *recordingMockFactory) Stop(context.Context) error                        { return nil }
func (f *recordingMockFactory) MetricViews() []sdkmetric.View                     { return nil }

func (f *recordingMockFactory) Validate(spec JobSpec) error {
	f.appConfigs = append(f.appConfigs, spec.AppConfig)
	return f.err
}

var (
	_ ServiceFactory          = (*recordingMockFactory)(nil)
	_ ServiceFactoryValidator = (*recordingMockFactory)(nil)
)

func TestValidateLocalAppConfig(t *testing.T) {
	t.Parallel()

	const appConfig = `
[[token_verifiers]]
verifier_id = "cctp-CCTPVerifier"
type = "cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
`

	t.Run("validates the app config referenced by the bootstrap config", func(t *testing.T) {
		t.Parallel()

		appPath := writeAppConfigFile(t, appConfig)
		bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml", localBootstrapTOML(appPath, ""))
		fac := &recordingMockFactory{}

		require.NoError(t, ValidateLocalAppConfig(bootstrapPath, fac))
		require.Equal(t, []string{appConfig}, fac.appConfigs)
	})

	t.Run("factory validation failures name the app config", func(t *testing.T) {
		t.Parallel()

		appPath := writeAppConfigFile(t, appConfig)
		bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml", localBootstrapTOML(appPath, ""))
		fac := &recordingMockFactory{err: errors.New("unknown keys for cctp verifier: [bogus]")}

		err := ValidateLocalAppConfig(bootstrapPath, fac)
		require.ErrorContains(t, err, "unknown keys for cctp verifier")
		require.ErrorContains(t, err, appPath)
	})

	t.Run("jd mode is rejected", func(t *testing.T) {
		t.Parallel()

		// A valid JD-mode bootstrap config: the mode check, not config validation, must reject it.
		const jdConfigTOML = `
[jd]
server_wsrpc_url = "ws://localhost:8080/ws"
server_csa_public_key = "` + validEd25519PublicKeyHex + `"

[server]
listen_port = 9988

[[chains]]
type = "EVM"
id = "1"

[db]
url = "postgres://localhost:5432/bootstrapper"

[keystore]
password = "s3cret"
`
		bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml", jdConfigTOML)
		fac := &recordingMockFactory{}

		err := ValidateLocalAppConfig(bootstrapPath, fac)
		require.ErrorContains(t, err, `requires "local_app_config"`)
		assert.Empty(t, fac.appConfigs)
	})

	t.Run("missing app config file errors", func(t *testing.T) {
		t.Parallel()

		missing := filepath.Join(t.TempDir(), "nope.toml")
		bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml", localBootstrapTOML(missing, ""))

		err := ValidateLocalAppConfig(bootstrapPath, &recordingMockFactory{})
		require.ErrorContains(t, err, missing)
	})

	t.Run("missing bootstrap config file errors", func(t *testing.T) {
		t.Parallel()

		missing := filepath.Join(t.TempDir(), "nope.toml")
		err := ValidateLocalAppConfig(missing, &recordingMockFactory{})
		require.ErrorContains(t, err, "invalid bootstrap config")
	})

	t.Run("local mode without local_app_config_path errors", func(t *testing.T) {
		t.Parallel()

		bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml",
			`app_config_mode = "local_app_config"`+"\n")

		err := ValidateLocalAppConfig(bootstrapPath, &recordingMockFactory{})
		require.ErrorContains(t, err, "local_app_config_path")
	})
}

// TestValidateLocalAppConfig_ConfigPathEnv is separate from the parallel test
// above because t.Setenv cannot be used in a parallel test.
func TestValidateLocalAppConfig_ConfigPathEnv(t *testing.T) {
	appPath := writeAppConfigFile(t, "[[token_verifiers]]\nverifier_id = \"x\"\n")
	bootstrapPath := writeFile(t, t.TempDir(), "bootstrap.toml", localBootstrapTOML(appPath, ""))
	t.Setenv(ConfigPathEnv, bootstrapPath)

	fac := &recordingMockFactory{}
	require.NoError(t, ValidateLocalAppConfig("", fac))
	require.Len(t, fac.appConfigs, 1)
}
