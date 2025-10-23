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
		CommitteeName:  "default",
		NodeIndex:      0,
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
