package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
)

func TestServiceVerifier(t *testing.T) {
	out, err := services.NewVerifier(&services.VerifierInput{
		SourceCodePath: "../../../verifier",
		RootPath:       "../../../../",
		SigningKey:     "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		Env: &services.VerifierEnvConfig{
			AggregatorAPIKey:    "test-api-key",
			AggregatorSecretKey: "test-secret-key",
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
