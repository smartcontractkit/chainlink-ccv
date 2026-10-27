package db

import (
	"database/sql"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/common/dblease"
)

// LeaseTable is the EVM database's lease table, created by migration 00002.
const LeaseTable = "evm.lease_lock"

// NewLease is the lease on the EVM database, with the node's default timings.
func NewLease(db *sql.DB, lggr logger.Logger) *dblease.Lease {
	return dblease.New(db, lggr, LeaseTable, dblease.DefaultConfig())
}
