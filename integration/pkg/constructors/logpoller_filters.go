package constructors

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// messageSentFilterRegistered reports whether the node's log poller has stored the named filter for chainID.
// It reads the table because the log poller's in-memory filters are empty until its first poll.
func messageSentFilterRegistered(ctx context.Context, ds sqlutil.DataSource, chainID *big.Int, name string) (bool, error) {
	var exists bool
	if err := ds.GetContext(ctx, &exists,
		`SELECT EXISTS (SELECT 1 FROM evm.log_poller_filters WHERE evm_chain_id = $1::numeric AND name = $2)`,
		chainID.String(), name); err != nil {
		return false, fmt.Errorf("failed to read log poller filter %s: %w", name, err)
	}
	return exists, nil
}

// newLogPollerConfig wires a chain's source reader to the node's log poller and database.
func newLogPollerConfig(ds sqlutil.DataSource, chain legacyevm.Chain, verifierID string) *evm.LogPollerConfig {
	return &evm.LogPollerConfig{
		LogPoller:  chain.LogPoller(),
		VerifierID: verifierID,
		Retention:  evm.DefaultMessageSentLogRetention,
		Ready:      new(atomic.Bool),
		FilterRegistered: func(ctx context.Context, name string) (bool, error) {
			return messageSentFilterRegistered(ctx, ds, chain.ID(), name)
		},
	}
}
