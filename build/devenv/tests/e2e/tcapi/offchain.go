package tcapi

import (
	"fmt"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
)

// SetupOffchainClients resolves the aggregator and indexer clients from the
// environment. When no offchain endpoints are configured it returns nil clients and
// a nil error; NewTestingContext skips assertion stages for nil clients. A non-nil
// error means a configured client failed to construct.
func SetupOffchainClients(lib ccv.Lib, aggregatorQualifier string) (*ccv.AggregatorClient, *ccv.IndexerMonitor, error) {
	aggregatorClients, err := lib.AllAggregators()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get aggregator clients: %w", err)
	}
	var aggregatorClient *ccv.AggregatorClient
	if len(aggregatorClients) > 0 {
		aggregatorClient = aggregatorClients[common.DefaultCommitteeVerifierQualifier]
		if aggregatorQualifier != "" && aggregatorQualifier != common.DefaultCommitteeVerifierQualifier {
			if client, ok := aggregatorClients[aggregatorQualifier]; ok {
				aggregatorClient = client
			}
		}
	}

	indexers, err := lib.AllIndexers()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get indexer clients: %w", err)
	}
	var indexerMonitor *ccv.IndexerMonitor
	if len(indexers) > 0 {
		indexerMonitor, err = lib.IndexerMonitor()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get indexer monitor: %w", err)
		}
	}
	return aggregatorClient, indexerMonitor, nil
}
