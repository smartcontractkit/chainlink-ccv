package admin

import (
	"context"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	recoverycli "github.com/smartcontractkit/chainlink-ccv/cli/recovery"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// NodeState is the per-node reachability state the UI renders. Unreachable is always
// shown separately from an empty result set.
type NodeState string

const (
	NodeStateReady       NodeState = "ready"
	NodeStateUnreachable NodeState = "unreachable"
)

// Node is one configured verifier database. The DB connection opens lazily on first
// use so the console starts even when a member is down.
type Node struct {
	cfg  NodeConfig
	lggr logger.Logger

	once sync.Once
	ds   *sqlx.DB
	err  error
}

func NewNode(cfg NodeConfig, lggr logger.Logger) *Node {
	return &Node{cfg: cfg, lggr: logger.With(lggr, "node", cfg.Name)}
}

func (n *Node) Name() string       { return n.cfg.Name }
func (n *Node) Config() NodeConfig { return n.cfg }

func (n *Node) connect() (*sqlx.DB, error) {
	n.once.Do(func() {
		n.ds, n.err = openNodeDB(n.lggr, n.cfg.SecretsPath)
	})
	return n.ds, n.err
}

// State probes the node's database with a short timeout. The error text is shown to
// operators; it contains no credentials (URLs never leave this package).
func (n *Node) State(ctx context.Context) (NodeState, string) {
	ds, err := n.connect()
	if err != nil {
		return NodeStateUnreachable, err.Error()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ds.PingContext(probeCtx); err != nil {
		return NodeStateUnreachable, "ping failed: " + err.Error()
	}
	return NodeStateReady, ""
}

func (n *Node) JobQueue() (jobqueue.Store, error) {
	ds, err := n.connect()
	if err != nil {
		return nil, err
	}
	return jobqueue.NewPostgresStore(ds), nil
}

func (n *Node) Recovery() (recoverycli.Store, error) {
	ds, err := n.connect()
	if err != nil {
		return nil, err
	}
	return recovery.NewStore(ds), nil
}

func (n *Node) ChainStatuses() (*chainstatus.PostgresChainStatusStore, error) {
	ds, err := n.connect()
	if err != nil {
		return nil, err
	}
	return chainstatus.NewPostgresChainStatusStore(ds, n.lggr), nil
}

func (n *Node) Close() {
	if n.ds != nil {
		_ = n.ds.Close()
	}
}
