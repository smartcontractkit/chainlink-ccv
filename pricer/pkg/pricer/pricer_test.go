package pricer

import (
	"context"
	"testing"
	"time"

	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/utils/big"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/stretchr/testify/require"
)

func ptr[T any](t T) *T { return &t }

func TestPricer(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	bcInput := &blockchain.Input{
		ChainID:       "1337",
		Type:          "geth",
		Port:          "8545",
		ContainerName: "test-pricer-geth",
	}
	bcOutput, err := blockchain.NewBlockchainNetwork(bcInput)
	require.NoError(t, err)

	chainID := big.NewI(1337)
	evmCfg := evmtoml.EVMConfig{
		ChainID: chainID,
		Nodes: []*evmtoml.Node{
			{
				Name:    ptr("test-pricer-geth"),
				WSURL:   commonconfig.MustParseURL(bcOutput.Nodes[0].ExternalWSUrl),
				HTTPURL: commonconfig.MustParseURL(bcOutput.Nodes[0].ExternalHTTPUrl),
			},
		},
	}

	// TODO: Move this to chainlink-evm/pkg/config/toml.
	defaults := evmtoml.Defaults(chainID)
	defaults.SetFrom(&evmCfg.Chain)
	evmCfg.Chain = defaults
	for _, n := range evmCfg.Nodes {
		_ = n.ValidateConfig()
	}

	// Create the EVM client using the same pattern as main.go.
	evmClient, err := NewEvmClientFromConfig(evmCfg, lggr)
	require.NoError(t, err)
	defer evmClient.Close()

	err = evmClient.Dial(ctx)
	require.NoError(t, err)

	// Verify we can query the chain.
	blockNum, err := evmClient.HeadByNumber(ctx, nil)
	require.NoError(t, err)
	t.Logf("current block number: %d", blockNum.BlockNumber())

	// Create and start the pricer.
	svc := New(lggr, evmClient, Config{Interval: commonconfig.MustNewDuration(1 * time.Second)})
	require.NoError(t, svc.Start(ctx))

	// Let it run for a few ticks.
	time.Sleep(3 * time.Second)

	// Verify clean shutdown.
	require.NoError(t, svc.Close())
}
