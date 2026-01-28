package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap/zapcore"

	selectors "github.com/smartcontractkit/chain-selectors"
	pricer "github.com/smartcontractkit/chainlink-ccv/pricer/pkg"
	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/evm"
	keys "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/sol"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	solcfg "github.com/smartcontractkit/chainlink-solana/pkg/solana/config"
)

// MonitoringConfig provides monitoring configuration for the pricer service.
// Prometheus metrics are always enabled and exposed via the standard /metrics endpoint.
type MonitoringConfig struct {
	Enabled bool `toml:"Enabled"`
	Port    int  `toml:"Port"`
}

type Config struct {
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// KMS configuration for transaction signing
	KMS keys.KMSConfig `toml:"KMS"`
	// Monitoring configuration for OpenTelemetry
	Monitoring MonitoringConfig `toml:"Monitoring"`

	// TODO: Other global pricerconfig.
	Interval commonconfig.Duration `toml:"interval"`
	// TODO: These will become lists of chains.
	// Chain write connectivity config,
	// common to read/write.
	EVM evm.ChainConfig `toml:"EVM"`
	SOL sol.ChainConfig `toml:"SOL"`
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
	// Set default monitoring port
	if c.Monitoring.Port == 0 {
		c.Monitoring.Port = 4141
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
	lggr       logger.Logger
	cfg        Config
	done       chan struct{}
	wg         sync.WaitGroup
	httpServer *http.Server
	chains     map[protocol.ChainSelector]pricer.Chain
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

	priceChains := make(map[protocol.ChainSelector]pricer.Chain)
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
		chainDetails, err := selectors.GetChainDetailsByChainIDAndFamily(cfg.EVM.ChainID.String(), selectors.FamilyEVM)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for EVM chain: %w", err)
		}
		selector := chainDetails.ChainSelector
		var evmChain *evm.Chain

		evmTxKeyStore, err := evmChain.CreateKeystore(ctx, cfg.KMS, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to create EVM keystore: %w", err)
		}
		evmChain, err = evm.LoadEVM(ctx, cfg.EVM, lggr, evmTxKeyStore, keystoreData, keystorePassword, pricerMonitoring)
		if err != nil {
			return nil, fmt.Errorf("failed to load EVM: %w", err)
		}
		priceChains[protocol.ChainSelector(selector)] = evmChain
		lggr.Infow("loaded EVM chain", "chainID", cfg.EVM.ChainID)
	} else {
		lggr.Infow("no EVM chain configured")
	}

	if cfg.SOL.ChainID != nil {
		chainDetails, err := selectors.GetChainDetailsByChainIDAndFamily(*cfg.SOL.ChainID, selectors.FamilySolana)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for Sol chain: %w", err)
		}
		selector := chainDetails.ChainSelector
		var solChain *sol.Chain

		solTxKeyStore, err := solChain.CreateKeystore(ctx, cfg.KMS, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to create Solana keystore: %w", err)
		}
		solChain, err = sol.LoadSolana(ctx, lggr, cfg.SOL, solTxKeyStore, keystoreData, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("failed to load solana: %w", err)
		}
		priceChains[protocol.ChainSelector(selector)] = solChain
		lggr.Infow("loaded solana chain", "chainID", cfg.SOL.ChainID)
	} else {
		lggr.Infow("no solana chain configured")
	}

	// Setup HTTP server for Prometheus metrics
	lggr.Infow("setting up HTTP server for Prometheus metrics", "port", cfg.Monitoring.Port)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))

	return &Pricer{
		StateMachine: services.StateMachine{},
		lggr:         lggr,
		cfg:          cfg,
		done:         make(chan struct{}),
		wg:           sync.WaitGroup{},
		httpServer: &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Monitoring.Port),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
		chains: priceChains,
	}, nil
}

func (p *Pricer) Start(ctx context.Context) error {
	return p.StartOnce("Pricer", func() error {
		// Start HTTP server for metrics
		listener, err := net.Listen("tcp", p.httpServer.Addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", p.httpServer.Addr, err)
		}
		p.wg.Go(func() {
			p.lggr.Infow("starting metrics HTTP server", "addr", p.httpServer.Addr)
			if err := p.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				p.lggr.Errorw("metrics HTTP server error", "error", err)
			}
		})

		for _, chain := range p.chains {
			if err := chain.Start(ctx); err != nil {
				return fmt.Errorf("failed to start chain: %w", err)
			}
		}
		p.wg.Go(func() {
			p.run(ctx)
		})
		return nil
	})
}

func (p *Pricer) run(ctx context.Context) {
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

			for _, chain := range p.chains {
				go func(chain pricer.Chain) {
					if err := chain.Tick(ctx); err != nil {
						p.lggr.Error("failed to tick chain", "error", err)
						return
					}
				}(chain)
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
		// Shutdown HTTP server first, then wait for goroutines to finish
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.httpServer.Shutdown(shutdownCtx); err != nil {
			p.lggr.Warnw("failed to shutdown metrics HTTP server", "error", err)
		}
		p.wg.Wait()

		// TODO: replace this with a done channel in the future
		for _, chain := range p.chains {
			if err := chain.Close(); err != nil {
				return fmt.Errorf("failed to close chain: %w", err)
			}
		}
		return nil
	})
}
