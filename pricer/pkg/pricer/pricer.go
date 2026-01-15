package pricer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap/zapcore"

	solanago "github.com/gagliardetto/solana-go"
	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/kms"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
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
	solclient "github.com/smartcontractkit/chainlink-solana/pkg/solana/client"
	solcfg "github.com/smartcontractkit/chainlink-solana/pkg/solana/config"
	solkeys "github.com/smartcontractkit/chainlink-solana/pkg/solana/keys"
	soltxm "github.com/smartcontractkit/chainlink-solana/pkg/solana/txm"
	solutils "github.com/smartcontractkit/chainlink-solana/pkg/solana/utils"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
)

type KMSConfig struct {
	Profile      string `toml:"profile"`
	EcdsaKeyID   string `toml:"ecdsa_key_id"`
	Ed25519KeyID string `toml:"ed25519_key_id"`
}

type Config struct {
	// TODO: Actual pricerconfig.
	Interval commonconfig.Duration `toml:"interval"`
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// Chain write connectivity config,
	// common to read/write.
	EVM evmtoml.EVMConfig `toml:"EVM"`
	SOL solcfg.TOMLConfig `toml:"SOL"`
	// KMS configuration for transaction signing
	KMS KMSConfig `toml:"KMS"`
}

func (c *Config) Validate() error {
	if c.Interval.Duration() <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if c.EVM.ChainID != nil {
		if err := c.EVM.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid EVM chain config: %w", err)
		}
	}
	if c.SOL.ChainID != nil {
		if err := c.SOL.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid Solana chain config: %w", err)
		}
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
	// Apply Solana chain defaults.
	if c.SOL.ChainID != nil {
		defaults := solcfg.Defaults()
		defaults.SetFrom(&c.SOL)
		c.SOL = defaults
	}
	// Validate Solana nodes to populate their defaults.
	for _, n := range c.SOL.Nodes {
		_ = n.ValidateConfig()
	}
}

type Pricer struct {
	services.StateMachine
	lggr     logger.Logger
	evmChain *evmChain
	solChain *solanaChain
	cfg      Config
	done     chan struct{}
	wg       sync.WaitGroup
}

type evmChain struct {
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

type solanaChain struct {
	client   *solclient.MultiNodeClient
	txm      *soltxm.Txm
	keystore core.Keystore
}

func (c *solanaChain) Start(ctx context.Context) error {
	return c.txm.Start(ctx)
}

func loadEVM(ctx context.Context, cfg Config, lggr logger.Logger, keystoreData []byte, keystorePassword string) (*evmChain, error) {
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
		client:   evmClient,
		txm:      evmTxm,
		keystore: evmTxKeyStore,
	}, nil
}

func createEVMKeystore(ctx context.Context, cfg Config, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.KMS.EcdsaKeyID != "" {
		kmsClient, err := kms.NewClient(ctx, kms.ClientOptions{
			Profile: cfg.KMS.Profile,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS client: %w", err)
		}
		keyStore, err := kms.NewKeystore(kmsClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS keystore: %w", err)
		}
		return evmkeys.NewTxKeyCoreKeystore(keyStore, evmkeys.WithAllowedKeyNames([]string{cfg.KMS.EcdsaKeyID})), nil
	}
	memStorage := ks.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	keyStore, err := ks.LoadKeystore(ctx, memStorage, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	return evmkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func createSolanaKeystore(ctx context.Context, cfg Config, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.KMS.Ed25519KeyID != "" {
		kmsClient, err := kms.NewClient(ctx, kms.ClientOptions{
			Profile: cfg.KMS.Profile,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS client: %w", err)
		}
		keyStore, err := kms.NewKeystore(kmsClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS keystore: %w", err)
		}
		return solkeys.NewTxKeyCoreKeystore(keyStore, solkeys.WithAllowedKeyNames([]string{cfg.KMS.Ed25519KeyID})), nil
	}
	memStorage := ks.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	keyStore, err := ks.LoadKeystore(ctx, memStorage, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	return solkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func loadSolana(ctx context.Context, lggr logger.Logger, cfg Config, keystoreData []byte, keystorePassword string) (*solanaChain, error) {
	solClient, err := solclient.NewMultiNodeClient(
		cfg.SOL.ListNodes()[0].URL.String(),
		&cfg.SOL,
		time.Second*10,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana client: %w", err)
	}
	solTxKeyStore, err := createSolanaKeystore(ctx, cfg, keystoreData, keystorePassword)
	if err != nil {
		return nil, err
	}
	solClientLoader := solutils.NewOnceLoader[solclient.ReaderWriter](func(ctx context.Context) (solclient.ReaderWriter, error) {
		return solClient, nil
	})
	solTxm, err := soltxm.NewTxm(
		*cfg.SOL.ChainID,
		solClientLoader,
		func(ctx context.Context, tx *solanago.Transaction) (solanago.Signature, error) {
			return solClient.SendTx(ctx, tx)
		},
		&cfg.SOL,
		solTxKeyStore,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana txm: %w", err)
	}
	return &solanaChain{
		client:   solClient,
		txm:      solTxm,
		keystore: solTxKeyStore,
	}, nil
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

	var evmChain *evmChain
	var solChain *solanaChain
	if cfg.EVM.ChainID != nil {
		evmChain, err = loadEVM(ctx, cfg, lggr, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to load EVM: %w", err)
		}
	}
	if cfg.SOL.ChainID != nil {
		solChain, err = loadSolana(ctx, lggr, cfg, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to load Solana: %w", err)
		}
	}
	return &Pricer{
		StateMachine: services.StateMachine{},
		lggr:         lggr,
		cfg:          cfg,
		done:         make(chan struct{}),
		wg:           sync.WaitGroup{},
		evmChain:     evmChain,
		solChain:     solChain,
	}, nil
}

func (p *Pricer) Start(ctx context.Context) error {
	return p.StartOnce("Pricer", func() error {
		if p.evmChain != nil {
			if err := p.evmChain.Start(ctx); err != nil {
				return fmt.Errorf("failed to start EVM chain: %w", err)
			}
		}
		if p.solChain != nil {
			if err := p.solChain.Start(ctx); err != nil {
				return fmt.Errorf("failed to start Solana chain: %w", err)
			}
		}
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
			if p.evmChain != nil {
				addresses, err := p.evmChain.keystore.Accounts(ctx)
				if err != nil {
					p.lggr.Error("failed to get addresses", "error", err)
					continue
				}
				if len(addresses) == 0 {
					p.lggr.Warn("no EVM addresses found in keystore")
					continue
				}
				balance, err := p.evmChain.client.BalanceAt(ctx, common.HexToAddress(addresses[0]), nil)
				if err != nil {
					p.lggr.Error("failed to get balance", "error", err)
					continue
				}
				p.lggr.Infow("balance", "address", addresses[0], "balance", balance)
			}
			if p.solChain != nil {
				addresses, err := p.solChain.keystore.Accounts(ctx)
				if err != nil {
					p.lggr.Error("failed to get addresses", "error", err)
					continue
				}
				if len(addresses) == 0 {
					p.lggr.Warn("no Solana addresses found in keystore")
					continue
				}
				balance, err := p.solChain.client.Balance(ctx, solanago.MustPublicKeyFromBase58(addresses[0]))
				if err != nil {
					p.lggr.Error("failed to get balance", "error", err)
					continue
				}
				p.lggr.Infow("balance", "address", addresses[0], "balance", balance)
			}

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
		if p.evmChain != nil {
			if err := p.evmChain.txm.Close(); err != nil {
				return fmt.Errorf("failed to close EVM txm: %w", err)
			}
			p.evmChain.client.Close()
		}
		if p.solChain != nil {
			if err := p.solChain.txm.Close(); err != nil {
				return fmt.Errorf("failed to close Solana txm: %w", err)
			}
			p.solChain.client.Close()
		}
		return nil
	})
}
