package ccv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadLocalConfigEnv loads the no-JD example env file and checks it decodes (strict, unknown
// fields rejected) and selects the local app-config source. This guards the env-local-config.toml
// example against drift in the Cfg schema without needing Docker.
func TestLoadLocalConfigEnv(t *testing.T) {
	in, err := Load[Cfg]([]string{"env-local-config.toml"})
	require.NoError(t, err, "env-local-config.toml must decode into Cfg")

	assert.Equal(t, AppConfigSourceLocal, in.AppConfigSource)
	assert.True(t, in.IsLocal(), "IsLocal must be true for app_config_source = local")

	// The no-JD example declares no Job Distributor, no executors, and at least one verifier.
	assert.Nil(t, in.JD, "local example must not declare a [jd] block")
	assert.Empty(t, in.Executor, "local example must not declare executors (JD-only, skipped in local mode)")
	require.NotEmpty(t, in.Verifier, "local example must declare a committee verifier")
}

// TestDefaultAppConfigSourceIsJD confirms the historical default: an env with no app_config_source
// resolves to the JD path (IsLocal false), so existing env files are unaffected.
func TestDefaultAppConfigSourceIsJD(t *testing.T) {
	var c Cfg
	assert.False(t, c.IsLocal())
	assert.Equal(t, AppConfigSource(""), c.AppConfigSource)
}
