package pricer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
)

type Config struct {
	// TODO: Actual pricerconfig.
	Interval time.Duration `toml:"interval"`
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// Chain write connectivity config,
	// common to read/write.
	EVM evmtoml.EVMConfig `toml:"EVM"`
}

func (c *Config) Validate() error {
	if c.Interval <= 0 {
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
}

type Pricer struct {
	services.StateMachine
	lggr   logger.Logger
	client client.Client
	txm    *txm.Txm
	cfg    Config
	done   chan struct{}
	wg     sync.WaitGroup
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

	evmClient, err := NewEvmClientFromConfig(lggr, cfg.EVM)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM client: %w", err)
	}

	// Use in-memory keystore storage populated from env var data.
	memStorage := keystore.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	ks, err := keystore.LoadKeystore(ctx, memStorage, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	txm := NewStatelessTxmV2FromConfig(lggr, cfg.EVM, evmClient, ks, nil)
	return New(lggr, cfg, evmClient, txm), nil
}

func New(lggr logger.Logger, cfg Config, evmClient client.Client, txm *txm.Txm) *Pricer {
	return &Pricer{
		StateMachine: services.StateMachine{},
		lggr:         lggr,
		client:       evmClient,
		cfg:          cfg,
		done:         make(chan struct{}),
		wg:           sync.WaitGroup{},
		txm:          txm,
	}
}

func (p *Pricer) Start(ctx context.Context) error {
	return p.StartOnce("Pricer", func() error {
		p.lggr.Infow("starting",
			"chainID", p.client.ConfiguredChainID(),
		)
		p.wg.Add(1)
		go p.run(ctx)
		return nil
	})
}

func (p *Pricer) run(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.Interval)
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
			p.lggr.Debug("tick")

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
