package admin

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	idxcommon "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	indexerconfig "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/replay"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

// Backfill (U2, optional): indexer-data repair for operators who own their indexer.
// The replay engine embeds cleanly in-process (no servers/signal handlers in
// replay.NewEngine — only indexer/cmd/replay's main has those); see report for evidence.

// replayRunner is the subset of the replay engine the console drives.
type replayRunner interface {
	Start(context.Context, replay.Request) (string, error)
}

// replayJobLister reads durable replay job state.
type replayJobLister interface {
	ListJobs(context.Context) ([]replay.Job, error)
}

// Test seams: swapped by backfill_test.go.
var backfillEngineFor = buildReplayEngine
var backfillJobsFor = openReplayJobLister

// backfillInFlight guards against double submission from this console process. It is
// not job state: durability and cross-process resume live in replay_jobs.
var backfillInFlight = struct {
	sync.Mutex
	running map[string]struct{}
}{running: map[string]struct{}{}}

func backfillClaim(key string) bool {
	backfillInFlight.Lock()
	defer backfillInFlight.Unlock()
	if _, ok := backfillInFlight.running[key]; ok {
		return false
	}
	backfillInFlight.running[key] = struct{}{}
	return true
}

func backfillRelease(key string) {
	backfillInFlight.Lock()
	defer backfillInFlight.Unlock()
	delete(backfillInFlight.running, key)
}

// backfillStores caches one replay store (a connection pool, not job state) per node.
var backfillStores = struct {
	sync.Mutex
	byKey map[string]replayJobLister
}{byKey: map[string]replayJobLister{}}

func (h *handlers) registerBackfillRoutes(r *gin.Engine) {
	r.GET("/backfill", h.backfillPage)
	r.POST("/backfill/submit", h.backfillSubmit)
	r.GET("/backfill/jobs", h.backfillJobs)
}

func (h *handlers) backfillNodes() []views.BackfillNodeVM {
	var nodes []views.BackfillNodeVM
	for _, n := range h.nodes {
		if n.Config().IndexerConfigPath != "" {
			nodes = append(nodes, views.BackfillNodeVM{Name: n.Name()})
		}
	}
	return nodes
}

func (h *handlers) backfillPage(c *gin.Context) {
	h.render(c, http.StatusOK, views.BackfillPage(h.csrfToken(c), h.backfillNodes()))
}

// parseBackfillRequest validates the two distinct backfill forms: discovery by
// aggregator sequence number XOR targeted repair by message IDs — never mixed, and
// never source block numbers.
func parseBackfillRequest(c *gin.Context) (replay.Request, error) {
	sinceStr := strings.TrimSpace(c.PostForm("since"))
	idsStr := strings.TrimSpace(c.PostForm("message_ids"))
	if sinceStr != "" && idsStr != "" {
		return replay.Request{}, errors.New("provide either an aggregator sequence number (discovery) or message IDs (targeted repair), not both")
	}
	force := c.PostForm("force") == "on"
	if sinceStr != "" {
		since, err := strconv.ParseInt(sinceStr, 10, 64)
		if err != nil {
			return replay.Request{}, fmt.Errorf("aggregator sequence number must be an unsigned decimal integer: %w", err)
		}
		return replay.Request{Type: replay.TypeDiscovery, Since: since, Force: force}, nil
	}
	if idsStr != "" {
		fields := strings.FieldsFunc(idsStr, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
		ids, err := jobqueue.ParseMessageIDs(fields)
		if err != nil {
			return replay.Request{}, err
		}
		msgIDs := make([]string, 0, len(ids))
		for _, id := range ids {
			msgIDs = append(msgIDs, "0x"+hex.EncodeToString(id))
		}
		return replay.Request{Type: replay.TypeMessages, MessageIDs: msgIDs, Force: force}, nil
	}
	return replay.Request{}, errors.New("a backfill target is required: an aggregator sequence number or a set of message IDs")
}

func (h *handlers) backfillSubmit(c *gin.Context) {
	if !h.requireActions(c) {
		return
	}
	res := views.BackfillSubmitResultVM{NodeName: c.PostForm("node")}
	n := h.node(res.NodeName)
	if n == nil {
		h.render(c, http.StatusNotFound, views.BackfillSubmitError("unknown node "+res.NodeName))
		return
	}
	if n.Config().IndexerConfigPath == "" {
		h.render(c, http.StatusBadRequest, views.BackfillSubmitError(
			"node "+res.NodeName+" has no indexer_config_path: backfill is available only for an indexer this operator owns"))
		return
	}
	req, err := parseBackfillRequest(c)
	if err != nil {
		h.render(c, http.StatusBadRequest, views.BackfillSubmitError(err.Error()))
		return
	}
	res.RequestHash = req.Hash()
	res.Target = backfillTarget(req)
	target := res.NodeName + " " + res.Target
	fail := func(status int, detail string) {
		res.Error = detail
		if logErr := h.recordAction(c, Action{
			Action: "backfill-submit", NodeName: res.NodeName, Target: target, Outcome: "failed", Detail: detail,
		}); logErr != nil {
			res.Error += " (action log write failed: " + logErr.Error() + ")"
		}
		h.render(c, status, views.BackfillSubmitResult(res))
	}
	claimKey := res.NodeName + "\x00" + res.RequestHash
	if !backfillClaim(claimKey) {
		fail(http.StatusConflict, "an identical replay is already running from this console; the job list below shows its progress")
		return
	}
	engine, cleanup, err := backfillEngineFor(c.Request.Context(), h.lggr, n)
	if err != nil {
		backfillRelease(claimKey)
		fail(http.StatusInternalServerError, "could not build the replay engine from the indexer config: "+err.Error())
		return
	}
	// Detached from the request: replays run minutes to hours. On console shutdown the
	// job stalls as running and is resumed by an identical resubmission (stale heartbeat).
	go func() {
		defer cleanup()
		defer backfillRelease(claimKey)
		jobID, err := engine.Start(context.Background(), req)
		if err != nil {
			h.lggr.Errorw("backfill replay failed", "node", res.NodeName, "jobID", jobID, "requestHash", res.RequestHash, "error", err)
		}
	}()
	res.JobID = h.backfillAwaitJob(c.Request.Context(), n, res.RequestHash)
	detail := "request_hash=" + res.RequestHash
	if res.JobID == "" {
		detail += " (job row not visible yet at response time)"
	}
	if logErr := h.recordAction(c, Action{
		Action: "backfill-submit", NodeName: res.NodeName, Target: target,
		OperationID: res.JobID, Outcome: "success", Detail: detail,
	}); logErr != nil {
		res.Error = "replay job was started but the action log write failed: " + logErr.Error()
	}
	h.render(c, http.StatusOK, views.BackfillSubmitResult(res))
}

// backfillAwaitJob correlates the just-launched run with its durable job row by
// request hash (the newest matching row wins, which is also the stale-resume row).
func (h *handlers) backfillAwaitJob(ctx context.Context, n *Node, hash string) string {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if lister, err := backfillJobsFor(ctx, h.lggr, n); err == nil {
			if jobs, err := lister.ListJobs(ctx); err == nil {
				best := ""
				var bestCreated time.Time
				for _, j := range jobs {
					if j.RequestHash == hash && !j.CreatedAt.Before(bestCreated) {
						best, bestCreated = j.ID, j.CreatedAt
					}
				}
				if best != "" {
					return best
				}
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func backfillTarget(req replay.Request) string {
	if req.Type == replay.TypeDiscovery {
		return fmt.Sprintf("discovery since aggregator sequence %d", req.Since)
	}
	return fmt.Sprintf("targeted repair of %d message ID(s)", len(req.MessageIDs))
}

func (h *handlers) backfillJobs(c *gin.Context) {
	var nodes []views.BackfillJobsNodeVM
	inFlight := false
	for _, n := range h.nodes {
		if n.Config().IndexerConfigPath == "" {
			continue
		}
		nvm := views.BackfillJobsNodeVM{NodeName: n.Name()}
		lister, err := backfillJobsFor(c.Request.Context(), h.lggr, n)
		if err != nil {
			nvm.Error = err.Error()
		} else if jobs, err := lister.ListJobs(c.Request.Context()); err != nil {
			nvm.Error = err.Error()
		} else {
			for _, j := range jobs {
				nvm.Jobs = append(nvm.Jobs, backfillJobVM(j))
				if j.Status == replay.StatusPending || j.Status == replay.StatusRunning {
					inFlight = true
				}
			}
		}
		nodes = append(nodes, nvm)
	}
	h.render(c, http.StatusOK, views.BackfillJobs(nodes, inFlight))
}

func backfillJobVM(j replay.Job) views.BackfillJobVM {
	vm := views.BackfillJobVM{
		ID: j.ID, Type: string(j.Type), Status: string(j.Status), Force: j.ForceOverwrite,
		CreatedAt: j.CreatedAt, Heartbeat: j.LastHeartbeat,
	}
	if j.ErrorMessage != nil {
		vm.Error = *j.ErrorMessage
	}
	if j.SinceSequenceNumber != nil {
		vm.Target = fmt.Sprintf("since aggregator sequence %d", *j.SinceSequenceNumber)
	} else {
		vm.Target = fmt.Sprintf("%d message ID(s)", len(j.MessageIDs))
		if len(j.MessageIDs) > 0 {
			vm.Target += ": " + strings.Join(j.MessageIDs[:min(len(j.MessageIDs), 3)], ", ")
			if len(j.MessageIDs) > 3 {
				vm.Target += ", …"
			}
		}
	}
	if j.TotalItems > 0 {
		vm.Progress = fmt.Sprintf("%d/%d (cursor %d)", j.ProcessedItems, j.TotalItems, j.ProgressCursor)
	} else {
		vm.Progress = fmt.Sprintf("%d processed (cursor %d)", j.ProcessedItems, j.ProgressCursor)
	}
	vm.Stale = j.Status == replay.StatusRunning && time.Since(j.LastHeartbeat) > replay.StaleJobTimeout
	return vm
}

// loadIndexerConfig reads an owned indexer's config from the operator-provided path,
// merging generated config and the sibling secrets.toml, without touching the
// process-wide INDEXER_* env vars (one console process serves many nodes).
func loadIndexerConfig(configPath string) (*indexerconfig.Config, error) {
	data, err := os.ReadFile(configPath) //nolint:gosec // G304: operator-provided console config path.
	if err != nil {
		return nil, fmt.Errorf("failed to read indexer config %q: %w", configPath, err)
	}
	cfg, err := indexerconfig.LoadConfigFromBytes(data)
	if err != nil {
		return nil, err
	}
	generated, err := indexerconfig.LoadGeneratedConfig(configPath, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load indexer generated config: %w", err)
	}
	indexerconfig.MergeGeneratedConfig(cfg, generated)
	secretsPath := filepath.Join(filepath.Dir(configPath), "secrets.toml")
	if secretsData, err := os.ReadFile(secretsPath); err == nil {
		secrets, err := indexerconfig.LoadSecretsFromBytes(secretsData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse indexer secrets %q: %w", secretsPath, err)
		}
		if err := indexerconfig.MergeSecrets(cfg, secrets); err != nil {
			return nil, fmt.Errorf("failed to merge indexer secrets %q: %w", secretsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read indexer secrets %q: %w", secretsPath, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("indexer config %q is invalid: %w", configPath, err)
	}
	return cfg, nil
}

func indexerPostgresConfig(cfg *indexerconfig.Config) (*indexerconfig.PostgresConfig, error) {
	if cfg.Storage.Single == nil || cfg.Storage.Single.Postgres == nil {
		return nil, errors.New("indexer config has no Storage.Single.Postgres section")
	}
	return cfg.Storage.Single.Postgres, nil
}

// indexerDBConfig mirrors the replay CLI's halved pool: the console is a sidecar to
// the live indexer, not a second full consumer of its database.
func indexerDBConfig(pgCfg *indexerconfig.PostgresConfig) pg.DBConfig {
	return pg.DBConfig{
		MaxOpenConns:           max(pgCfg.MaxOpenConnections/2, 2),
		MaxIdleConns:           max(pgCfg.MaxIdleConnections/2, 1),
		IdleInTxSessionTimeout: time.Duration(pgCfg.IdleInTxSessionTimeout) * time.Second,
		LockTimeout:            time.Duration(pgCfg.LockTimeout) * time.Second,
	}
}

// openReplayJobLister opens a read-side replay store for one node's indexer DB. The
// caller caches it per node; the pool lives for the console's lifetime.
func openReplayJobLister(ctx context.Context, lggr logger.Logger, n *Node) (replayJobLister, error) {
	key := n.Name() + "\x00" + n.Config().IndexerConfigPath
	backfillStores.Lock()
	defer backfillStores.Unlock()
	if store, ok := backfillStores.byKey[key]; ok {
		return store, nil
	}
	cfg, err := loadIndexerConfig(n.Config().IndexerConfigPath)
	if err != nil {
		return nil, err
	}
	pgCfg, err := indexerPostgresConfig(cfg)
	if err != nil {
		return nil, err
	}
	store, err := replay.NewStoreFromConfig(ctx, lggr, pgCfg.URI, indexerDBConfig(pgCfg),
		time.Duration(pgCfg.ConnMaxLifetime), time.Duration(pgCfg.ConnMaxIdleTime))
	if err != nil {
		return nil, fmt.Errorf("failed to open the indexer replay store: %w", err)
	}
	backfillStores.byKey[key] = store
	return store, nil
}

var initChainSelectorCacheOnce sync.Once

// buildReplayEngine mirrors indexer/cmd/replay's mustBuildEngine, minus CLI fatals,
// signal handling and migrations — schema ownership stays with the indexer
// deployment; a missing replay schema surfaces as the store's error.
func buildReplayEngine(ctx context.Context, lggr logger.Logger, n *Node) (replayRunner, func(), error) {
	cfg, err := loadIndexerConfig(n.Config().IndexerConfigPath)
	if err != nil {
		return nil, nil, err
	}
	pgCfg, err := indexerPostgresConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	mon := monitoring.NewNoopIndexerMonitoring()
	initChainSelectorCacheOnce.Do(protocol.InitChainSelectorCache)
	dbConfig := indexerDBConfig(pgCfg)
	lifetime, idle := time.Duration(pgCfg.ConnMaxLifetime), time.Duration(pgCfg.ConnMaxIdleTime)

	replayStore, err := replay.NewStoreFromConfig(ctx, lggr, pgCfg.URI, dbConfig, lifetime, idle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create replay store: %w", err)
	}
	indexerStorage, err := storage.NewPostgresStorage(ctx, lggr, mon, pgCfg.URI, pg.DriverPostgres, dbConfig, lifetime, idle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create indexer storage: %w", err)
	}
	cleanups := []func(){}
	fail := func(err error) (replayRunner, func(), error) {
		for _, cleanup := range cleanups {
			cleanup()
		}
		return nil, nil, err
	}
	verifierRegistry := registry.NewVerifierRegistry()
	for i := range cfg.Verifiers {
		vc := &cfg.Verifiers[i]
		vr, cleanup, err := newReplayVerifierReader(ctx, lggr, vc, mon, cfg.Resilience)
		if err != nil {
			return fail(fmt.Errorf("failed to create verifier reader %q: %w", vc.Label(), err))
		}
		cleanups = append(cleanups, cleanup)
		for _, address := range vc.IssuerAddresses {
			issuer, err := protocol.NewUnknownAddressFromHex(address)
			if err != nil {
				return fail(fmt.Errorf("invalid issuer address %q: %w", address, err))
			}
			if err := verifierRegistry.AddVerifier(issuer, vc.Name, vr); err != nil {
				return fail(fmt.Errorf("failed to register verifier %q: %w", address, err))
			}
		}
	}
	var aggFactory replay.AggregatorReaderFactory
	if len(cfg.Discoveries) > 0 {
		disc := cfg.Discoveries[0]
		aggFactory = func(since int64) (*readers.ResilientReader, error) {
			metrics := mon.Metrics().With("target", disc.Label())
			return readers.NewAggregatorReader(disc.Address, lggr, since, hmac.ClientConfig{
				APIKey: disc.APIKey, Secret: disc.Secret,
			}, disc.InsecureConnection, indexerconfig.EffectiveMaxResponseBytes(disc.MaxResponseBytes), metrics, readers.NewResilienceConfig(cfg.Resilience))
		}
	}
	engine := replay.NewEngine(replayStore, indexerStorage, verifierRegistry, aggFactory, lggr)
	cleanup := func() {
		for _, c := range cleanups {
			c()
		}
	}
	return engine, cleanup, nil
}

// newReplayVerifierReader mirrors the CLI's per-verifier reader construction.
func newReplayVerifierReader(ctx context.Context, lggr logger.Logger, vc *indexerconfig.VerifierConfig, mon idxcommon.IndexerMonitoring, resilience indexerconfig.ResilienceConfig) (*readers.VerifierReader, func(), error) {
	metrics := mon.Metrics().With("target", vc.Label())
	var resilientReader *readers.ResilientReader
	var err error
	switch vc.Type {
	case indexerconfig.ReaderTypeAggregator:
		resilientReader, err = readers.NewAggregatorReader(vc.Address, lggr, vc.Since, hmac.ClientConfig{
			APIKey: vc.APIKey, Secret: vc.Secret,
		}, vc.InsecureConnection, indexerconfig.EffectiveMaxResponseBytes(vc.MaxResponseBytes), metrics, readers.NewResilienceConfig(resilience))
	case indexerconfig.ReaderTypeRest:
		resilientReader = readers.NewRestReader(readers.RestReaderConfig{
			BaseURL:          vc.BaseURL,
			RequestTimeout:   time.Duration(vc.RequestTimeout),
			MaxResponseBytes: indexerconfig.EffectiveMaxResponseBytes(vc.MaxResponseBytes),
			Logger:           lggr,
			Metrics:          metrics,
			Resilience:       readers.NewResilienceConfig(resilience),
		})
	default:
		return nil, nil, errors.New("unknown verifier reader type: " + string(vc.Type))
	}
	if err != nil {
		return nil, nil, err
	}
	vr := readers.NewVerifierReader(resilientReader, vc)
	if err := vr.Start(ctx); err != nil {
		return nil, nil, err
	}
	return vr, func() { _ = vr.Close() }, nil
}
