package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestServiceExecutor(t *testing.T) {
	// Minimal valid executor config for testing
	generatedConfig := `
executor_id = "executor-test"
indexer_address = "http://localhost:8100"

[chain_configuration]
[chain_configuration."1"]
off_ramp_address = "0x0000000000000000000000000000000000000001"
rmn_address = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
execution_interval = "15s"
executor_pool = ["executor-test"]
`

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
	out, err := services.NewExecutor(&services.ExecutorInput{
		SourceCodePath:  "../../../executor",
		RootPath:        "../../../../",
		ContainerName:   "executor-test",
		Port:            8101,
		Mode:            services.Standalone,
		GeneratedConfig: generatedConfig,
	}, blockchainOutputs)
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
