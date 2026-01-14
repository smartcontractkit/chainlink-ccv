package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

var verifierTestCredentials = hmacutil.MustGenerateCredentials()

func TestServiceVerifier(t *testing.T) {
	in := services.ApplyVerifierDefaults(services.VerifierInput{
		SourceCodePath: "../../../verifier",
		RootPath:       "../../../../",
		CommitteeName:  "default",
		NodeIndex:      0,
		Env: &services.VerifierEnvConfig{
			AggregatorAPIKey:    verifierTestCredentials.APIKey,
			AggregatorSecretKey: verifierTestCredentials.Secret,
		},
	})
	out, err := services.NewVerifier(&in)
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
