package pricer

import (
	"context"
	"errors"
	"sync"
	"time"

	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

var DefaultInterval = commonconfig.MustNewDuration(10 * time.Second)

type Config struct {
	Interval *commonconfig.Duration `toml:"interval"`
}

func (c *Config) Validate() error {
	if c.Interval == nil || c.Interval.Duration() <= 0 {
		return errors.New("interval must be positive")
	}
	return nil
}

func (c *Config) SetDefaults() {
	if c.Interval == nil {
		c.Interval = DefaultInterval
	}
}

type Pricer struct {
	services.StateMachine
	lggr   logger.Logger
	client client.Client
	cfg    Config
	done   chan struct{}
	wg     sync.WaitGroup
}

func New(lggr logger.Logger, evmClient client.Client, cfg Config) *Pricer {
	return &Pricer{
		StateMachine: services.StateMachine{},
		lggr:         lggr,
		client:       evmClient,
		cfg:          cfg,
		done:         make(chan struct{}),
		wg:           sync.WaitGroup{},
	}
}

func (p *Pricer) Start(ctx context.Context) error {
	return p.StartOnce("Pricer", func() error {
		p.lggr.Infow("starting", "interval", p.cfg.Interval.Duration())
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
			// TODO: fetch and report prices
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
