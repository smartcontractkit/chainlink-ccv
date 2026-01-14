package pricer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/keystore"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/clientwrappers"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
)

type Config struct {
	// TODO: Actual pricerconfig.
	Interval commonconfig.Duration `toml:"interval"`
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// Chain write connectivity config,
	// common to read/write.
	EVM evmtoml.EVMConfig `toml:"EVM"`
}

func (c *Config) Validate() error {
	if c.Interval.Duration() <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if err := c.EVM.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid EVM chain config: %w", err)
	}
	return nil
}

func (c *Config) SetDefaults() {
	if c.LogLevel == zapcore.Level(0) {
		c.LogLevel = zapcore.InfoLevel
	}
	// Apply EVM chain defaults based on chainID.
	if c.EVM.ChainID != nil {
		defaults := evmtoml.Defaults(c.EVM.ChainID)
		defaults.SetFrom(&c.EVM.Chain)
		c.EVM.Chain = defaults
	}
	// Validate nodes to populate their defaults.
	for _, n := range c.EVM.Nodes {
		_ = n.ValidateConfig()
	}
}

type Pricer struct {
	services.StateMachine
	lggr        logger.Logger
	client      client.Client
	txm         *txm.Txm
	txmKeyStore keys.Store
	cfg         Config
	done        chan struct{}
	wg          sync.WaitGroup
}

func NewPricerFromConfig(ctx context.Context, cfg Config, keystoreData []byte, keystorePassword string) (*Pricer, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	lggr, err := logger.NewWith(logging.DevelopmentConfig(cfg.LogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Named(lggr, "pricer")

	chainScopedCfg := evmconfig.NewTOMLChainScopedConfig(&cfg.EVM)
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

	// Use in-memory keystore storage populated from env var data.
	memStorage := keystore.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	keyStore, err := keystore.LoadKeystore(ctx, memStorage, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	txKeyCoreKeystore := evmkeys.NewTxKeyCoreKeystore(keyStore)
	txmKeyStore := keys.NewStore(txKeyCoreKeystore)

	// Get enabled addresses from keystore to register with the store manager.
	addresses, err := txmKeyStore.EnabledAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled addresses: %w", err)
	}

	inMemoryStoreManager := storage.NewInMemoryStoreManager(lggr, evmClient.ConfiguredChainID())
	// Register addresses with the in-memory store so TXM can manage transactions.
	if err := inMemoryStoreManager.Add(addresses...); err != nil {
		return nil, fmt.Errorf("failed to add addresses to store manager: %w", err)
	}
	txmClient := clientwrappers.NewChainClient(evmClient)
	priceMaxKey := func(addr common.Address) *assets.Wei {
		return chainScopedCfg.EVM().GasEstimator().PriceMax()
	}
	chainStore := keys.NewChainStore(txKeyCoreKeystore, evmClient.ConfiguredChainID())
	attemptBuilder := txm.NewAttemptBuilder(priceMaxKey, nil, chainStore, 0)

	txm := txm.NewTxm(
		lggr,
		evmClient.ConfiguredChainID(),
		txmClient,
		attemptBuilder,
		inMemoryStoreManager,
		nil, // stuckTxDetector
		txm.Config{
			EIP1559:   chainScopedCfg.EVM().GasEstimator().EIP1559DynamicFees(),
			BlockTime: *chainScopedCfg.EVM().Transactions().TransactionManagerV2().BlockTime(),
		},
		txmKeyStore,
		nil, // errorHandler
	)
	return New(lggr, cfg, evmClient, txm, txmKeyStore), nil
}

func New(lggr logger.Logger, cfg Config, evmClient client.Client, txm *txm.Txm, txmKeyStore keys.Store) *Pricer {
	return &Pricer{
		StateMachine: services.StateMachine{},
		lggr:         lggr,
		client:       evmClient,
		cfg:          cfg,
		done:         make(chan struct{}),
		wg:           sync.WaitGroup{},
		txm:          txm,
		txmKeyStore:  txmKeyStore,
	}
}

func (p *Pricer) Start(ctx context.Context) error {
	return p.StartOnce("Pricer", func() error {
		// Dial the EVM client to start the connection pool.
		if err := p.client.Dial(ctx); err != nil {
			return fmt.Errorf("failed to dial EVM client: %w", err)
		}
		if err := p.txm.Start(ctx); err != nil {
			return fmt.Errorf("failed to start Txm: %w", err)
		}
		addresses, err := p.txmKeyStore.EnabledAddresses(ctx)
		if err != nil {
			return fmt.Errorf("failed to get enabled addresses: %w", err)
		}
		p.lggr.Infow("starting",
			"chainID", p.client.ConfiguredChainID(),
			"addresses", addresses,
		)
		p.wg.Add(1)
		go p.run(ctx)
		return nil
	})
}

func (p *Pricer) run(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.Interval.Duration())
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			p.lggr.Info("stopped")
			return
		case <-ctx.Done():
			p.lggr.Info("context cancelled")
			return
		case <-ticker.C:
			p.lggr.Info("tick")
			address, err := p.txmKeyStore.GetNextAddress(ctx)
			if err != nil {
				p.lggr.Error("failed to get next address", "error", err)
				continue
			}
			balance, err := p.client.BalanceAt(ctx, address, nil)
			if err != nil {
				p.lggr.Error("failed to get balance", "error", err)
				continue
			}
			p.lggr.Infow("balance", "address", address, "balance", balance)

			/*
				// TODO: fetch and report prices
				// Unsigned transaction request
				tx, err := p.txm.CreateTransaction(ctx, &types.TxRequest{})
				if err != nil {
					p.lggr.Error("failed to get enabled addresses", "error", err)
					continue
				}
				p.txm.Trigger(tx.FromAddress)
			*/
		}
	}
}

func (p *Pricer) Close() error {
	return p.StopOnce("Pricer", func() error {
		close(p.done)
		p.wg.Wait()
		p.client.Close()
		return nil
	})
}
