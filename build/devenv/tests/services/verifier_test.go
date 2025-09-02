package services_test

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/stretchr/testify/require"
)

func TestServiceVerifier(t *testing.T) {
	out, err := services.NewVerifier(&services.VerifierInput{SourceCodePath: "../../../verifier"})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
