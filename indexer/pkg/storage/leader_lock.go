package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/pgadvisorylock"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
)

// discoveryLockKey is the name of the advisory lock that allows one discovery leader across all replicas.
const discoveryLockKey = "indexer_discovery"

var _ common.DiscoveryLocker = (*PostgresStorage)(nil)

// TryAcquireDiscoveryLock holds the discovery advisory lock on a dedicated connection.
// The server frees the lock if no heartbeat comes for leaseTimeout.
func (d *PostgresStorage) TryAcquireDiscoveryLock(ctx context.Context, leaseTimeout time.Duration) (common.DiscoveryLock, bool, error) {
	lock, acquired, err := pgadvisorylock.TryAcquire(ctx, d.ds, discoveryLockKey, leaseTimeout)
	if err != nil || !acquired {
		return nil, acquired, err
	}
	return lock, true, nil
}
