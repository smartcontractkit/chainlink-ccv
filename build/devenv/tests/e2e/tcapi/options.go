// Test wiring is configured with functional options (WithLane, WithAggregatorClients,
// WithIndexerMonitor). Pass those to case constructors—for example basic.All or
// token_transfer.All—alongside a deployment.Environment. BuildCaseDeps resolves options
// inside those subpackages into CaseDeps; external test code should not call it directly.
package tcapi

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// CaseDeps holds dependencies wired at construction time for TestCase implementations.
type CaseDeps struct {
	Env               *deployment.Environment
	DataStore         datastore.DataStore
	SrcSelector       uint64
	DstSelector       uint64
	AggregatorClients map[string]*ccv.AggregatorClient
	IndexerMonitor    *ccv.IndexerMonitor
	ChainMap          map[uint64]cciptestinterfaces.CCIP17
}

type caseConfig struct {
	env         *deployment.Environment
	srcSel      uint64
	dstSel      uint64
	laneSet     bool
	aggregators map[string]*ccv.AggregatorClient
	indexer     *ccv.IndexerMonitor
}

// CaseOption configures lane-scoped tests when passed to constructors (e.g. basic.All,
// token_transfer.All). Prefer the exported With* helpers rather than calling BuildCaseDeps directly.
type CaseOption func(*caseConfig) error

// WithLane selects the source and destination chain selectors for lane-scoped tests.
func WithLane(srcSel, dstSel uint64) CaseOption {
	return func(c *caseConfig) error {
		c.srcSel, c.dstSel = srcSel, dstSel
		c.laneSet = true
		return nil
	}
}

// WithAggregatorClients sets aggregator clients keyed by committee verifier qualifier (optional).
func WithAggregatorClients(m map[string]*ccv.AggregatorClient) CaseOption {
	return func(c *caseConfig) error {
		if m != nil {
			c.aggregators = m
		}
		return nil
	}
}

// WithIndexerMonitor sets an indexer monitor for optional indexing assertions (optional).
func WithIndexerMonitor(m *ccv.IndexerMonitor) CaseOption {
	return func(c *caseConfig) error {
		c.indexer = m
		return nil
	}
}

func resolveCaseConfig(env *deployment.Environment, opts ...CaseOption) (*caseConfig, error) {
	cfg := &caseConfig{
		env:         env,
		aggregators: make(map[string]*ccv.AggregatorClient),
	}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	if env == nil {
		return nil, fmt.Errorf("deployment.Environment is required")
	}
	if !cfg.laneSet {
		return nil, fmt.Errorf("tcapi.WithLane(srcSel, dstSel) is required")
	}
	return cfg, nil
}

// BuildCaseDeps resolves CaseOptions into CaseDeps (CCIP17 handles and optional off-chain clients).
// It is intended for use inside this module (basic and token_transfer packages), not as the primary
// API for test authors; pass CaseOptions built from the With* functions to those constructors instead.
func BuildCaseDeps(ctx context.Context, env *deployment.Environment, opts ...CaseOption) (*CaseDeps, error) {
	rc, err := resolveCaseConfig(env, opts...)
	if err != nil {
		return nil, err
	}
	lg := zerolog.Ctx(ctx)
	src, err := ccv.NewCCIP17ForChainSelector(ctx, *lg, env, rc.srcSel)
	if err != nil {
		return nil, fmt.Errorf("src chain selector %d: %w", rc.srcSel, err)
	}
	dst, err := ccv.NewCCIP17ForChainSelector(ctx, *lg, env, rc.dstSel)
	if err != nil {
		return nil, fmt.Errorf("dst chain selector %d: %w", rc.dstSel, err)
	}
	chainMap := map[uint64]cciptestinterfaces.CCIP17{
		rc.srcSel: src,
		rc.dstSel: dst,
	}
	return &CaseDeps{
		Env:               env,
		DataStore:         env.DataStore,
		SrcSelector:       rc.srcSel,
		DstSelector:       rc.dstSel,
		AggregatorClients: rc.aggregators,
		IndexerMonitor:    rc.indexer,
		ChainMap:          chainMap,
	}, nil
}
