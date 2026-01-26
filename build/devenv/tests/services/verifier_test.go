package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
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
		GeneratedConfig: `
verifier_id = "default-verifier-1"
aggregator_address = "default-aggregator:50051"
insecure_aggregator_connection = true
signer_address = "0x9A676e781A523b5d0C0e43731313A708CB607508"
pyroscope_url = "http://host.docker.internal:4040"

[committee_verifier_addresses]
"16015286601757825753" = "0x9A676e781A523b5d0C0e43731313A708CB607508"
`,
	})
	blockchainOutputs := make([]*blockchain.Output, 1)
	blockchainOutputs[0] = &blockchain.Output{
		ChainID: "1337",
		Family:  "evm",
		Type:    "anvil",
		Nodes: []*blockchain.Node{
			{
				ExternalHTTPUrl: "http://host.docker.internal:8545",
				InternalHTTPUrl: "http://blockchain-src:8545",
				ExternalWSUrl:   "ws://host.docker.internal:8545",
				InternalWSUrl:   "ws://blockchain-src:8545",
			},
		},
	}
	out, err := services.NewVerifier(&in, blockchainOutputs)
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
