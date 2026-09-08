package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForwardedAWSEnv(t *testing.T) {
	// t.Setenv resets each var after the test, so this does not leak into other tests.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")
	t.Setenv("AWS_REGION", "us-west-2")
	// Empty values are treated as unset and excluded.
	t.Setenv("AWS_DEFAULT_REGION", "")

	got := ForwardedAWSEnv()

	require.Equal(t, map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
		"AWS_REGION":            "us-west-2",
	}, got)
	require.NotContains(t, got, "AWS_DEFAULT_REGION", "empty env var must be excluded")
}

func TestForwardedAWSEnv_ReturnsEmptyNonNilWhenUnset(t *testing.T) {
	for _, k := range awsCredentialEnvVars {
		t.Setenv(k, "")
	}

	got := ForwardedAWSEnv()

	require.NotNil(t, got, "must return a non-nil map so callers can merge unconditionally")
	require.Empty(t, got)
}

func TestForwardedGCPCreds(t *testing.T) {
	// t.Setenv resets each var after the test, so this does not leak into other tests.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/host/path/sa.json")

	env, files := ForwardedGCPCreds()

	require.Equal(t, map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/host/path/sa.json"}, env)
	require.Len(t, files, 1)
	require.Equal(t, "/host/path/sa.json", files[0].HostFilePath)
	require.Equal(t, "/host/path/sa.json", files[0].ContainerFilePath, "key file must be mounted at the path ADC reads")
	// The service images run as a non-root user while testcontainers copies files in as uid 0, so
	// anything stricter than world-readable makes the credentials unopenable by the process.
	require.Equal(t, int64(0o644), files[0].FileMode, "key file must be readable by the container's non-root user")
}

func TestForwardedGCPCreds_EmptyNonNilWhenUnset(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	env, files := ForwardedGCPCreds()

	require.NotNil(t, env, "must return a non-nil map so callers can merge unconditionally")
	require.Empty(t, env)
	require.Empty(t, files)
}
