package tcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// stubLib is a minimal ccv.Lib test double. Absence is expressed by leaving the
// plural-getter fields empty; a construction failure by setting the *Err fields.
type stubLib struct {
	aggregators       map[string]*ccv.AggregatorClient
	aggregatorsErr    error
	indexers          []*client.IndexerClient
	allIndexersErr    error
	indexerMonitor    *ccv.IndexerMonitor
	indexerMonitorErr error
}

func (s *stubLib) Chains(context.Context) ([]ccv.ChainImpl, error) { return nil, nil }
func (s *stubLib) ChainsMap(context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	return nil, nil
}
func (s *stubLib) CLDFEnvironment() (*deployment.Environment, error) { return nil, nil }
func (s *stubLib) DataStore() (datastore.DataStore, error)           { return nil, nil }
func (s *stubLib) Indexer() (*client.IndexerClient, error)           { return nil, nil }
func (s *stubLib) IndexerMonitor() (*ccv.IndexerMonitor, error) {
	return s.indexerMonitor, s.indexerMonitorErr
}

func (s *stubLib) AllIndexers() ([]*client.IndexerClient, error) {
	return s.indexers, s.allIndexersErr
}

func (s *stubLib) AllAggregators() (map[string]*ccv.AggregatorClient, error) {
	return s.aggregators, s.aggregatorsErr
}

func (s *stubLib) V3Source(context.Context, uint64) (cciptestinterfaces.V3Source, error) {
	return nil, nil
}

func (s *stubLib) V3Destination(context.Context, uint64) (cciptestinterfaces.V3Destination, error) {
	return nil, nil
}

var _ ccv.Lib = (*stubLib)(nil)

// presentIndexers is a non-empty indexer slice for the "configured" branch; the
// element only needs to be non-nil for the length check.
func presentIndexers() []*client.IndexerClient { return []*client.IndexerClient{{}} }

func TestSetupOffchainClients(t *testing.T) {
	defaultAgg := &ccv.AggregatorClient{}
	secondaryAgg := &ccv.AggregatorClient{}

	tests := []struct {
		name      string
		lib       *stubLib
		qualifier string
		wantErr   bool
		wantAgg   *ccv.AggregatorClient // nil expects a nil aggregator client
		wantIdx   bool                  // expect a non-nil indexer monitor
	}{
		{
			name: "both absent",
			lib:  &stubLib{},
		},
		{
			name: "both present",
			lib: &stubLib{
				aggregators:    map[string]*ccv.AggregatorClient{common.DefaultCommitteeVerifierQualifier: defaultAgg},
				indexers:       presentIndexers(),
				indexerMonitor: &ccv.IndexerMonitor{},
			},
			wantAgg: defaultAgg,
			wantIdx: true,
		},
		{
			name: "qualifier override, indexer absent",
			lib: &stubLib{
				aggregators: map[string]*ccv.AggregatorClient{
					common.DefaultCommitteeVerifierQualifier: defaultAgg,
					"secondary":                              secondaryAgg,
				},
			},
			qualifier: "secondary",
			wantAgg:   secondaryAgg,
		},
		{
			name:    "aggregator construction fails",
			lib:     &stubLib{aggregatorsErr: errors.New("connection refused")},
			wantErr: true,
		},
		{
			name: "indexer monitor construction fails",
			lib: &stubLib{
				indexers:          presentIndexers(),
				indexerMonitorErr: errors.New("dial tcp: connection refused"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg, idx, err := SetupOffchainClients(tt.lib, tt.qualifier)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantAgg == nil {
				assert.Nil(t, agg)
			} else {
				assert.Same(t, tt.wantAgg, agg)
			}
			if tt.wantIdx {
				assert.NotNil(t, idx)
			} else {
				assert.Nil(t, idx)
			}
		})
	}
}
