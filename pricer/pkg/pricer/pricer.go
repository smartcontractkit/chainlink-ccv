package pricer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/keystore"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"go.uber.org/zap/zapcore"
)

var DefaultInterval = commonconfig.MustNewDuration(10 * time.Second)

type PricerConfig struct {
	Interval *commonconfig.Duration `toml:"interval"`
}

func (c *PricerConfig) Validate() error {
	if c.Interval == nil || c.Interval.Duration() <= 0 {
		return errors.New("interval must be positive")
	}
	return nil
}

func (c *PricerConfig) SetDefaults() {
	if c.Interval == nil {
		c.Interval = DefaultInterval
	}
}

type Config struct {
	// Product specific config.
	PricerConfig
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// EVM chain configuration.
	EVM evmtoml.EVMConfig `toml:"EVM"`
}

func (c *Config) Validate() error {
	if err := c.PricerConfig.Validate(); err != nil {
		return fmt.Errorf("invalid pricer config: %w", err)
	}
	if err := c.EVM.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid EVM config: %w", err)
	}
	return nil
}

func (c *Config) SetDefaults() {
	c.PricerConfig.SetDefaults()
	if c.LogLevel == zapcore.Level(0) {
		c.LogLevel = zapcore.InfoLevel
	}
	// Apply chain-specific defaults based on ChainID.
	if c.EVM.ChainID != nil {
		defaults := evmtoml.Defaults(c.EVM.ChainID)
		defaults.SetFrom(&c.EVM.Chain)
		c.EVM.Chain = defaults
	}
	// Node.ValidateConfig() sets defaults for Order, IsLoadBalancedRPC, etc.
	for _, n := range c.EVM.Nodes {
		_ = n.ValidateConfig()
	}
}

// Family specific writer
// List of abstract data sources.
type Pricer struct {
	services.StateMachine
	lggr   logger.Logger
	client client.Client
	txm    *txm.Txm
	cfg    PricerConfig
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewPricerFromConfig(ctx context.Context, cfg Config, keystorePassword string, ksFile string) (*Pricer, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	lggr, err := logger.NewWith(logging.DevelopmentConfig(cfg.LogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Named(lggr, "pricer")

	// Build the EVM client from config.
	// TODO: Move this to chainlink-evm/pkg/client.
	evmClient, err := NewEvmClientFromConfig(lggr, cfg.EVM)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM client: %w", err)
	}
	ks, err := keystore.LoadKeystore(ctx, keystore.NewFileStorage(ksFile), keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	txm := NewStatelessTxmV2FromConfig(lggr, cfg.EVM, evmClient, ks, nil)
	return New(lggr, cfg.PricerConfig, evmClient, txm), nil
}

func New(lggr logger.Logger, cfg PricerConfig, evmClient client.Client, txm *txm.Txm) *Pricer {
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
			"interval", p.cfg.Interval.Duration(),
			"chainID", p.client.ConfiguredChainID(),
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
