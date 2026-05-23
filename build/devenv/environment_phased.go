package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// NewPhasedEnvironment creates a new CCIP CCV environment using the phased
// component runtime. It loads the raw TOML config, hands control to the
// runtime, then reconstructs *Cfg from the loaded TOML and the runtime outputs.
func NewPhasedEnvironment() (cfg *Cfg, err error) {
	ctx := L.WithContext(context.Background())

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	rawConfig, err := loadRaw(configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// out is captured by the defer; its contents are available when the defer fires.
	var out map[string]any
	defer func() {
		var elapsed float64
		if timeTrack, ok := out["_time_track"].(*timing.TimeTracker); ok && timeTrack != nil {
			timeTrack.Print()
			elapsed = timeTrack.SinceStart().Seconds()
		}
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, elapsed)
	}()

	out, err = devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, devenvruntime.GlobalRegistry(), newDevenvEffectExecutor(), L)
	if err != nil {
		return nil, err
	}

	// TODO: Remove this load and do not use "Cfg" as the return type.
	cfg, err = Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("loading config for output: %w", err)
	}

	// Sync blockchains from Phase 1 so Out fields (RPC URLs, etc.) are populated.
	if blockchains, ok := out["blockchains"].([]*blockchain.Input); ok {
		cfg.Blockchains = blockchains
	}

	// Sync CLDF state (addresses + env metadata) from protocol_contracts Phase 2.
	if cldf, ok := out["_cldf"].(*ccldf.CLDF); ok && cldf != nil {
		cfg.CLDF.Addresses = cldf.Addresses
		cfg.CLDF.EnvMetadata = cldf.EnvMetadata
	}

	// Replace cfg.Aggregator with started inputs from the committeeccv component
	// so Store() persists the launched Out fields and aggregator endpoint maps.
	if aggregators, ok := out["aggregators"].([]*services.AggregatorInput); ok {
		cfg.Aggregator = aggregators
		cfg.AggregatorEndpoints = make(map[string]string)
		cfg.AggregatorCACertFiles = make(map[string]string)
		for _, agg := range aggregators {
			if agg.Out != nil {
				cfg.AggregatorEndpoints[agg.CommitteeName] = agg.Out.ExternalHTTPSUrl
				if agg.Out.TLSCACertFile != "" {
					cfg.AggregatorCACertFiles[agg.CommitteeName] = agg.Out.TLSCACertFile
				}
			}
		}
	}

	// Replace cfg.Verifier with started inputs from the committeeccv component.
	if verifiers, ok := out["verifiers"].([]*committeeverifier.Input); ok {
		cfg.Verifier = verifiers
	}

	// Collect indexer outputs from the indexer Phase 4 component.
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

	// Replace cfg.TokenVerifier with started inputs from the tokenverifier component.
	if tokenVerifiers, ok := out["token_verifier"].([]*services.TokenVerifierInput); ok {
		cfg.TokenVerifier = tokenVerifiers
	}

	return cfg, Store(cfg)
}
