package pricer

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/keystore"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/utils/big"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func ptr[T any](t T) *T { return &t }

func TestPricer(t *testing.T) {
	ctx := context.Background()
	bcInput := &blockchain.Input{
		ChainID:       "1337",
		Type:          "geth",
		Port:          "8545",
		ContainerName: "test-pricer-geth",
	}
	bcOutput, err := blockchain.NewBlockchainNetwork(bcInput)
	require.NoError(t, err)

	// TODO: Move this to chainlink-evm/pkg/config/toml.
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
	defaults := evmtoml.Defaults(chainID)
	defaults.SetFrom(&evmCfg.Chain)
	evmCfg.Chain = defaults
	// TODO: why don't defaults work here?
	evmCfg.Transactions.TransactionManagerV2.BlockTime = commonconfig.MustNewDuration(12 * time.Second)
	for _, n := range evmCfg.Nodes {
		_ = n.ValidateConfig()
	}

	// Create a keystore and populate it with a key.
	tmpfile, err := os.CreateTemp("", "keystore.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	fileStorage := keystore.NewFileStorage(tmpfile.Name())
	ks, err := keystore.LoadKeystore(ctx, fileStorage, "password")
	require.NoError(t, err)
	txKey, err := evmkeys.CreateTxKey(ks, "key1")
	require.NoError(t, err)
	t.Logf("txKey address: %s", txKey.Address())

	// Read the keystore data to simulate env var input.
	keystoreData, err := fileStorage.GetEncryptedKeystore(ctx)
	require.NoError(t, err)

	svc, err := NewPricerFromConfig(ctx,
		Config{
			Interval: 1 * time.Second,
			LogLevel: zapcore.DebugLevel,
			EVM:      evmCfg,
		}, keystoreData, "password")
	require.NoError(t, err)
	require.NoError(t, svc.Start(ctx))
	// Let it run for a few ticks.
	time.Sleep(3 * time.Second)
	svc.Close()
}
