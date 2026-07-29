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
