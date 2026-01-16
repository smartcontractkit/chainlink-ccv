package pricer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/kms"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	solcfg "github.com/smartcontractkit/chainlink-solana/pkg/solana/config"
)

// KMSConfig provides global KMS configuration for the pricer service.
// Global as we imagine key re-use across chains.
type KMSConfig struct {
	Profile      string `toml:"profile"`
	EcdsaKeyID   string `toml:"ecdsa_key_id"`
	Ed25519KeyID string `toml:"ed25519_key_id"`
}

// MonitoringConfig provides monitoring configuration for the pricer service.
// Prometheus metrics are always enabled and exposed via the standard /metrics endpoint.
type MonitoringConfig struct {
	Enabled bool `toml:"Enabled"`
}

type Config struct {
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// KMS configuration for transaction signing
	KMS KMSConfig `toml:"KMS"`
	// Monitoring configuration for OpenTelemetry
	Monitoring MonitoringConfig `toml:"Monitoring"`

	// TODO: Other global pricerconfig.
	Interval commonconfig.Duration `toml:"interval"`
	// TODO: These will become lists of chains.
	// Chain write connectivity config,
	// common to read/write.
	EVM EVMChainConfig `toml:"EVM"`
	SOL SOLChainConfig `toml:"SOL"`
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
	if c.Monitoring.Enabled {
		if err := c.Monitoring.Validate(); err != nil {
			return fmt.Errorf("invalid monitoring config: %w", err)
		}
	}
	return nil
}

// Validate performs validation on the monitoring configuration.
func (m *MonitoringConfig) Validate() error {
	// No validation needed for Prometheus metrics
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
		defaults.SetFrom(&c.SOL.TOMLConfig)
		c.SOL.TOMLConfig = defaults
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

func loadKMSKeystore(ctx context.Context, profile string) (interface {
	ks.Reader
	ks.Signer
}, error,
) {
	kmsClient, err := kms.NewClient(ctx, kms.ClientOptions{
		Profile: profile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	return kms.NewKeystore(kmsClient)
}

func loadMemoryKeystore(ctx context.Context, keystoreData []byte, keystorePassword string) (interface {
	ks.Reader
	ks.Signer
}, error,
) {
	memStorage := ks.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	return ks.LoadKeystore(ctx, memStorage, keystorePassword)
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

	// Setup Prometheus monitoring if enabled
	var pricerMonitoring monitoring.Monitoring
	if cfg.Monitoring.Enabled {
		chainID := "unknown"
		if cfg.EVM.ChainID != nil {
			chainID = cfg.EVM.ChainID.String()
		}
		pricerMonitoring = monitoring.NewPricerMonitoring(chainID)
	} else {
		pricerMonitoring = monitoring.NewNoopPricerMonitoring()
	}

	if cfg.EVM.ChainID != nil {
		evmChain, err = loadEVM(ctx, cfg, lggr, keystoreData, keystorePassword, pricerMonitoring)
		if err != nil {
			return nil, fmt.Errorf("failed to load EVM: %w", err)
		}
		lggr.Infow("loaded EVM chain", "chainID", cfg.EVM.ChainID)
	} else {
		lggr.Infow("no EVM chain configured")
	}
	if cfg.SOL.ChainID != nil {
		solChain, err = loadSolana(ctx, lggr, cfg, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to load solana: %w", err)
		}
		lggr.Infow("loaded solana chain", "chainID", cfg.SOL.ChainID)
	} else {
		lggr.Infow("no solana chain configured")
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
			p.evmChain.lggr.Infow("started evm chain")
		}
		if p.solChain != nil {
			if err := p.solChain.Start(ctx); err != nil {
				return fmt.Errorf("failed to start Solana chain: %w", err)
			}
			p.solChain.lggr.Infow("started solana chain")
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
				if err := p.evmChain.Tick(ctx); err != nil {
					p.lggr.Error("failed to tick EVM chain", "error", err)
					continue
				}
			}
			if p.solChain != nil {
				if err := p.solChain.Tick(ctx); err != nil {
					p.lggr.Error("failed to tick Solana chain", "error", err)
					continue
				}
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
			if err := p.evmChain.Close(); err != nil {
				return fmt.Errorf("failed to close EVM txm: %w", err)
			}
		}
		if p.solChain != nil {
			if err := p.solChain.Close(); err != nil {
				return fmt.Errorf("failed to close Solana txm: %w", err)
			}
		}
		return nil
	})
}
