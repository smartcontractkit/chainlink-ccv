package evm

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	ks "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/monitoring"
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

type EvmChain struct {
	lggr     logger.Logger
	client   client.Client
	txm      *txm.Txm
	keystore core.Keystore
	metrics  *monitoring.PricerMetricLabeler
}

func (c *EvmChain) Start(ctx context.Context) error {
	// Dial the EVM client to start the connection pool.
	if err := c.client.Dial(ctx); err != nil {
		return fmt.Errorf("failed to dial EVM client: %w", err)
	}
	err := c.txm.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start EVM txm: %w", err)
	}
	c.lggr.Infow("started evm chain")
	return nil
}

func (c *EvmChain) Tick(ctx context.Context) error {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.metrics.RecordEVMTickDuration(duration)
	}()

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

func (c *EvmChain) Close() error {
	if err := c.txm.Close(); err != nil {
		return fmt.Errorf("failed to close EVM txm: %w", err)
	}
	c.client.Close()
	return nil
}

func (c *EvmChain) CreateKeystore(ctx context.Context, cfg ks.KMSConfig, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.EcdsaKeyID != "" {
		keyStore, err := ks.LoadKMSKeystore(ctx, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to load KMS keystore: %w", err)
		}
		return evmkeys.NewTxKeyCoreKeystore(keyStore, evmkeys.WithAllowedKeyNames([]string{cfg.EcdsaKeyID})), nil
	}
	keyStore, err := ks.LoadMemoryKeystore(ctx, keystoreData, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load memory keystore: %w", err)
	}
	return evmkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func LoadEVM(ctx context.Context, cfg EVMChainConfig, lggr logger.Logger, evmTxKeyStore core.Keystore, keystoreData []byte, keystorePassword string, pricerMonitoring monitoring.Monitoring) (*EvmChain, error) {
	chainScopedCfg := evmconfig.NewTOMLChainScopedConfig(&cfg.EVMConfig)
	nodePoolCfg := &evmconfig.NodePoolConfig{C: cfg.NodePool}
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

	return &EvmChain{
		lggr:     logger.Named(lggr, "evm"),
		client:   evmClient,
		txm:      evmTxm,
		keystore: evmTxKeyStore,
		metrics:  pricerMonitoring.Metrics(),
	}, nil
}
