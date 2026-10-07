package admin

import (
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	recoverycli "github.com/smartcontractkit/chainlink-ccv/cli/recovery"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// stores bundles the read/write surfaces the console uses over the verifier's own
// application database. The caller (the verifier process) owns the handle and has
// already applied the verifier migrations, the admin action log included.
type stores struct {
	db   *sqlx.DB
	lggr logger.Logger
}

func (s stores) JobQueue() jobqueue.Store { return jobqueue.NewPostgresStore(s.db) }

func (s stores) Recovery() recoverycli.Store { return recovery.NewStore(s.db) }

func (s stores) ChainStatuses() *chainstatus.PostgresChainStatusStore {
	return chainstatus.NewPostgresChainStatusStore(s.db, s.lggr)
}
