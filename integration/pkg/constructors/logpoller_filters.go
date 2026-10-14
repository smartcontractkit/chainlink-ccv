package constructors

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

// filterLoader is the slice of the log poller ORM that reads the stored filters.
type filterLoader interface {
	LoadFilters(ctx context.Context) (map[string]logpoller.Filter, error)
}

// filterRegistered reports whether the node's log poller has stored the named filter.
// It reads the database because the log poller's in-memory filters are empty until its first poll.
func filterRegistered(ctx context.Context, orm filterLoader, name string) (bool, error) {
	filters, err := orm.LoadFilters(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load log poller filters: %w", err)
	}
	_, ok := filters[name]
	return ok, nil
}

// newLogPollerConfig wires a chain's log poller source reader to the node's log poller and database.
func newLogPollerConfig(ds sqlutil.DataSource, chain legacyevm.Chain, verifierID string, lggr logger.Logger) *evm.LogPollerConfig {
	orm := logpoller.NewORM(chain.ID(), ds, lggr)
	return &evm.LogPollerConfig{
		LogPoller:  chain.LogPoller(),
		VerifierID: verifierID,
		Retention:  evm.DefaultMessageSentLogRetention,
		FilterRegistered: func(ctx context.Context, name string) (bool, error) {
			return filterRegistered(ctx, orm, name)
		},
	}
}
