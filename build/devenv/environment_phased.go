package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// NewPhasedEnvironment creates a new CCIP CCV environment using the phased
// component runtime. It loads the raw TOML config, hands control to the
// runtime, and extracts the resulting *Cfg produced by the legacy fallback
// component (see legacy_component.go).
func NewPhasedEnvironment() (in *Cfg, err error) {
	ctx := L.WithContext(context.Background())

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	rawConfig, err := loadRaw(configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	out, err := devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, devenvruntime.GlobalRegistry(), newDevenvEffectExecutor(), L)
	if err != nil {
		return nil, err
	}

	cfg, ok := out[legacyCfgKey].(*Cfg)
	if !ok {
		return nil, fmt.Errorf("runtime did not return a *Cfg")
	}

	// Collect indexer outputs from the "indexer" key published by the indexer
	// Phase 4 component. The component decodes its own inputs from TOML (new
	// pointers), so cfg.Indexer still has the unstarted Legacy Phase 2 copies.
	// Replace cfg.Indexer here so Store() persists the launched Out fields.
	if indexers, ok := out["indexer"].([]*services.IndexerInput); ok {
		cfg.Indexer = indexers
		externalURLs := make([]string, 0, len(indexers))
		internalURLs := make([]string, 0, len(indexers))
		for _, idxIn := range indexers {
			if idxIn.Out != nil {
				externalURLs = append(externalURLs, idxIn.Out.ExternalHTTPURL)
				internalURLs = append(internalURLs, idxIn.Out.InternalHTTPURL)
			}
		}
		cfg.IndexerEndpoints = externalURLs
		cfg.IndexerInternalEndpoints = internalURLs
	}

	// Replace cfg.TokenVerifier with the started inputs from the tokenverifier
	// component so Store() persists the launched Out fields.
	if tokenVerifiers, ok := out["token_verifier"].([]*services.TokenVerifierInput); ok {
		cfg.TokenVerifier = tokenVerifiers
	}

	return cfg, Store(cfg)
}

// runPhasedEnvironmentFinish collects aggregator endpoints, seals the datastore,
// and emits startup metrics. Job spec generation and proposal are now handled by
// the executor and committeeccv Phase 4 components.
func runPhasedEnvironmentFinish(
	in *Cfg,
	e *deployment.Environment,
	ds datastore.MutableDataStore,
	timeTrack *timing.TimeTracker,
) (err error) {
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	// Collect aggregator endpoints from Out fields populated by the CommitteeCCV Phase 4 component.
	in.AggregatorEndpoints = make(map[string]string)
	in.AggregatorCACertFiles = make(map[string]string)
	for _, agg := range in.Aggregator {
		if agg.Out != nil {
			in.AggregatorEndpoints[agg.CommitteeName] = agg.Out.ExternalHTTPSUrl
			if agg.Out.TLSCACertFile != "" {
				in.AggregatorCACertFiles[agg.CommitteeName] = agg.Out.TLSCACertFile
			}
		}
	}

	e.DataStore = ds.Seal()
	timeTrack.Print()
	return nil
}
