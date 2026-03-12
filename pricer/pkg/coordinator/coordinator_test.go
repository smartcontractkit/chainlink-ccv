package coordinator

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	evmchain "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/evm"
	solchain "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/sol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/utils/big"
	"github.com/smartcontractkit/chainlink-solana/pkg/solana/config"
	solkeys "github.com/smartcontractkit/chainlink-solana/pkg/solana/keys"
	soltesting "github.com/smartcontractkit/chainlink-solana/pkg/solana/testing"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func ptr[T any](t T) *T { return &t }

func TestPricer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
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
	evmChainID := big.NewI(1337)
	evmCfg := evmtoml.EVMConfig{
		ChainID: evmChainID,
		Nodes: []*evmtoml.Node{
			{
				Name:    ptr("test-pricer-geth"),
				WSURL:   commonconfig.MustParseURL(bcOutput.Nodes[0].ExternalWSUrl),
				HTTPURL: commonconfig.MustParseURL(bcOutput.Nodes[0].ExternalHTTPUrl),
			},
		},
	}
	defaults := evmtoml.Defaults(evmChainID)
	defaults.SetFrom(&evmCfg.Chain)
	evmCfg.Chain = defaults
	// TODO: why don't defaults work here?
	evmCfg.Transactions.TransactionManagerV2.BlockTime = commonconfig.MustNewDuration(12 * time.Second)
	for _, n := range evmCfg.Nodes {
		_ = n.ValidateConfig()
	}

	solURL, _ := soltesting.SetupLocalSolNodeWithFlags(t)
	solChainID := "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	solCfg := config.TOMLConfig{
		ChainID: &solChainID,
		Nodes: []*config.Node{
			{
				Name:     ptr("test-pricer-solana"),
				URL:      commonconfig.MustParseURL(solURL),
				Order:    ptr(int32(1)),
				SendOnly: false,
			},
		},
	}
	solCfg.SetDefaults()
	for _, n := range solCfg.Nodes {
		_ = n.ValidateConfig()
	}

	// Create a keystore and populate it with keys.
	tmpfile, err := os.CreateTemp("", "keystore.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	fileStorage := keystore.NewFileStorage(tmpfile.Name())
	ks, err := keystore.LoadKeystore(ctx, fileStorage, "password")
	require.NoError(t, err)

	_, err = evmkeys.CreateTxKey(ks, "evm-key1")
	require.NoError(t, err)
	_, err = solkeys.CreateTxKey(ks, "sol-key1")
	require.NoError(t, err)

	// Read the keystore data to simulate env var input.
	keystoreData, err := fileStorage.GetEncryptedKeystore(ctx)
	require.NoError(t, err)

	svc, err := NewPricerFromConfig(ctx,
		Config{
			Interval: *commonconfig.MustNewDuration(1 * time.Second),
			LogLevel: zapcore.DebugLevel,
			EVM:      evmchain.ChainConfig{EVMConfig: evmCfg},
			SOL:      solchain.ChainConfig{TOMLConfig: solCfg},
		}, keystoreData, "password")
	require.NoError(t, err)
	require.NoError(t, svc.Start(ctx))
	// Let it run for a few ticks.
	time.Sleep(5 * time.Second)
	require.NoError(t, svc.Close())
}
