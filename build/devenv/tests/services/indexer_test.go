package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestServiceIndexer(t *testing.T) {
	out, err := services.NewIndexer(&services.IndexerInput{
		SourceCodePath: "../../../indexer",
		RootPath:       "../../../../",
		GeneratedCfg: &config.GeneratedConfig{
			Verifier: map[string]config.GeneratedVerifierConfig{
				"0": {IssuerAddresses: []string{"0x9A676e781A523b5d0C0e43731313A708CB607508"}},
			},
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
