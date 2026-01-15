package pricer

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/clientwrappers"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
)

type EVMChainConfig struct {
	evmtoml.EVMConfig
	// Extend with pricer-specific config here if needed.
}

type evmChain struct {
	lggr     logger.Logger
	client   client.Client
	txm      *txm.Txm
	keystore core.Keystore
}

func (c *evmChain) Start(ctx context.Context) error {
	// Dial the EVM client to start the connection pool.
	if err := c.client.Dial(ctx); err != nil {
		return fmt.Errorf("failed to dial EVM client: %w", err)
	}
	return c.txm.Start(ctx)
}

func (c *evmChain) Tick(ctx context.Context) error {
	c.lggr.Infow("getting evm addresses")
	addresses, err := c.keystore.Accounts(ctx)
	if err != nil {
		c.lggr.Error("failed to get addresses", "error", err)
		return fmt.Errorf("failed to get addresses: %w", err)
	}
	if len(addresses) == 0 {
		c.lggr.Warn("no EVM addresses found in keystore")
		return fmt.Errorf("no EVM addresses found in keystore")
	}
	balance, err := c.client.BalanceAt(ctx, common.HexToAddress(addresses[0]), nil)
	if err != nil {
		c.lggr.Error("failed to get balance", "error", err)
		return fmt.Errorf("failed to get balance: %w", err)
	}
	c.lggr.Infow("got balance", "address", addresses[0], "balance", balance)
	return nil
}

func (c *evmChain) Close() error {
	if err := c.txm.Close(); err != nil {
		return fmt.Errorf("failed to close EVM txm: %w", err)
	}
	c.client.Close()
	return nil
}

func createEVMKeystore(ctx context.Context, cfg Config, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.KMS.EcdsaKeyID != "" {
		keyStore, err := loadKMSKeystore(ctx, cfg.KMS.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to load KMS keystore: %w", err)
		}
		return evmkeys.NewTxKeyCoreKeystore(keyStore, evmkeys.WithAllowedKeyNames([]string{cfg.KMS.EcdsaKeyID})), nil
	}
	keyStore, err := loadMemoryKeystore(ctx, keystoreData, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load memory keystore: %w", err)
	}
	return evmkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func loadEVM(ctx context.Context, cfg Config, lggr logger.Logger, keystoreData []byte, keystorePassword string) (*evmChain, error) {
	chainScopedCfg := evmconfig.NewTOMLChainScopedConfig(&cfg.EVM.EVMConfig)
	nodePoolCfg := &evmconfig.NodePoolConfig{C: cfg.EVM.NodePool}
	evmClient, err := client.NewEvmClient(
		nodePoolCfg,
		chainScopedCfg.EVM(),
		nodePoolCfg.Errors(),
		lggr,
		chainScopedCfg.EVM().ChainID(),
		chainScopedCfg.Nodes(),
		chainScopedCfg.EVM().ChainType(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM client: %w", err)
	}
	evmTxKeyStore, err := createEVMKeystore(ctx, cfg, keystoreData, keystorePassword)
	if err != nil {
		return nil, err
	}
	txmKeyStore := keys.NewStore(evmTxKeyStore)
	addresses, err := txmKeyStore.EnabledAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled addresses: %w", err)
	}
	inMemoryStoreManager := storage.NewInMemoryStoreManager(lggr, evmClient.ConfiguredChainID())
	if err := inMemoryStoreManager.Add(addresses...); err != nil {
		return nil, fmt.Errorf("failed to add addresses to store manager: %w", err)
	}
	txmClient := clientwrappers.NewChainClient(evmClient)
	priceMaxKey := func(addr common.Address) *assets.Wei {
		return chainScopedCfg.EVM().GasEstimator().PriceMax()
	}
	chainStore := keys.NewChainStore(evmTxKeyStore, evmClient.ConfiguredChainID())
	attemptBuilder := txm.NewAttemptBuilder(priceMaxKey, nil, chainStore, 0)
	evmTxm := txm.NewTxm(
		lggr,
		evmClient.ConfiguredChainID(),
		txmClient,
		attemptBuilder,
		inMemoryStoreManager,
		nil, // stuckTxDetector
		txm.Config{},
		txmKeyStore,
		nil, // errorHandler
	)
	return &evmChain{
		lggr:     logger.Named(lggr, "evm"),
		client:   evmClient,
		txm:      evmTxm,
		keystore: evmTxKeyStore,
	}, nil
}
