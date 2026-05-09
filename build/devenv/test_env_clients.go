package ccv

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
)

// NewAggregatorClientsFromCfg dials one AggregatorClient per entry in cfg.AggregatorEndpoints.
func NewAggregatorClientsFromCfg(ctx context.Context, cfg *Cfg) (map[string]*AggregatorClient, error) {
	out := make(map[string]*AggregatorClient)
	for qualifier := range cfg.AggregatorEndpoints {
		l := zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("aggregator-client-%s", qualifier)).Logger()
		c, err := cfg.NewAggregatorClientForCommittee(l, qualifier)
		if err != nil {
			return nil, err
		}
		if c == nil {
			return nil, fmt.Errorf("aggregator client is nil for qualifier %s", qualifier)
		}
		out[qualifier] = c
	}
	return out, nil
}

// FirstIndexerMonitorFromEndpoints returns the first indexer monitor built from the given HTTP(S)
// endpoints, or (nil, nil) when endpoints are empty or no client could be created (graceful).
func FirstIndexerMonitorFromEndpoints(ctx context.Context, endpoints []string, base zerolog.Logger) (*IndexerMonitor, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	for _, endpoint := range endpoints {
		ic, err := client.NewIndexerClient(endpoint, httpClient)
		if err != nil {
			base.Error().Err(err).Str("endpoint", endpoint).Msg("failed to create IndexerClient")
			continue
		}
		l := base.With().Str("component", fmt.Sprintf("indexer-client-%s", ic.URI())).Logger()
		mon, err := NewIndexerMonitor(l, ic)
		if err != nil {
			base.Error().Err(err).Str("endpoint", endpoint).Msg("failed to create IndexerMonitor")
			continue
		}
		return mon, nil
	}
	return nil, nil
}
