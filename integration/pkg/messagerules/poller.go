package messagerules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	shared "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DefaultPollInterval  = 2 * time.Second
	DefaultClientTimeout = 5 * time.Second
)

type PollerService struct {
	services.StateMachine
	stopCh        services.StopChan
	wg            sync.WaitGroup
	client        Client
	mutex         sync.RWMutex
	rules         shared.CompiledRules
	hasRules      bool
	pollInterval  time.Duration
	clientTimeout time.Duration
	lggr          logger.Logger
	metrics       common.MessageRulesCheckerMetrics
}

var _ common.MessageRulesCheckerService = (*PollerService)(nil)

func NewPollerService(client Client, pollInterval, clientTimeout time.Duration, lggr logger.Logger, metrics common.MessageRulesCheckerMetrics) (*PollerService, error) {
	if client == nil {
		return nil, fmt.Errorf("message rules client is required")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	if clientTimeout <= 0 {
		clientTimeout = DefaultClientTimeout
	}

	return &PollerService{
		stopCh:        make(chan struct{}),
		client:        client,
		pollInterval:  pollInterval,
		clientTimeout: clientTimeout,
		lggr:          lggr,
		metrics:       metrics,
	}, nil
}

func (s *PollerService) Start(ctx context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.poll(ctx)
			s.pollLoop()
		})

		s.lggr.Infow("Message rules service started", "pollInterval", s.pollInterval)
		return nil
	})
}

func (s *PollerService) Close() error {
	return s.StopOnce(s.Name(), func() error {
		s.lggr.Infow("Message rules service stopping")
		close(s.stopCh)
		s.wg.Wait()
		if err := s.client.Close(); err != nil {
			return err
		}
		s.lggr.Infow("Message rules service stopped")
		return nil
	})
}

func (s *PollerService) IsMessageDisabled(_ context.Context, message protocol.Message) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if !s.hasRules {
		return true, common.ErrMessageRulesStateUnknown
	}
	return s.rules.IsDisabled(shared.NewMessageReport(message)), nil
}

func (s *PollerService) pollLoop() {
	ctx, cancel := s.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

func (s *PollerService) poll(ctx context.Context) {
	timeoutCtx, cancel := context.WithTimeout(ctx, s.clientTimeout)
	defer cancel()

	rules, err := s.client.ListMessageRules(timeoutCtx)
	if err != nil {
		s.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 1)
		s.lggr.Errorw("Failed to refresh message rules; keeping previous rules", "error", err)
		return
	}

	compiled, err := shared.CompileRules(rules)
	if err != nil {
		s.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 1)
		s.lggr.Errorw("Failed to compile message rules; keeping previous rules", "error", err, "ruleCount", len(rules))
		return
	}

	s.mutex.Lock()
	s.rules = compiled
	s.hasRules = true
	s.mutex.Unlock()

	s.lggr.Infow("Refreshed message rules", "ruleCount", compiled.ActiveRuleCount())
	s.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 0)
}

func (s *PollerService) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

func (s *PollerService) Name() string {
	return "messagerules.PollerService"
}
