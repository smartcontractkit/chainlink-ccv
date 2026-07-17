package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	controlPlaneTimeout    = 10 * time.Second
	defaultJobStartTimeout = 60 * time.Second
	shutdownTimeout        = 5 * time.Second
)

// State represents the current state of the job lifecycle manager.
type State int

const (
	// StateWaitingForJob indicates the manager is waiting for a job proposal from JD.
	StateWaitingForJob State = iota
	// StateRunning indicates the manager has an active job running.
	StateRunning
)

// String returns a human-readable string representation of the state.
func (s State) String() string {
	switch s {
	case StateWaitingForJob:
		return "WaitingForJob"
	case StateRunning:
		return "Running"
	default:
		return "Unknown"
	}
}

// JobRunner is implemented by services that process jobs from JD.
// The lifecycle manager calls these methods to start and stop jobs.
type JobRunner interface {
	// StartJob starts processing a job with the given spec.
	// Called when a new job is proposed (initial or replacement).
	// The spec is the raw job specification string from JD.
	StartJob(ctx context.Context, spec string) error

	// StopJob stops the currently running job.
	// Called before a replacement job starts or on delete.
	// Should be idempotent - safe to call even if no job is running.
	StopJob(ctx context.Context) error
}

// ValidatingJobRunner is an optional extension for runners that can validate a replacement
// without changing the active job or allocating runtime resources. The manager performs this
// preflight before stopping the current job. Runners that implement only JobRunner retain the
// stop-then-start replacement flow.
type ValidatingJobRunner interface {
	JobRunner

	// ValidateJob checks the replacement spec without changing readiness, starting processing,
	// or allocating resources that require cleanup.
	ValidateJob(ctx context.Context, spec string) error
}

// Config holds the configuration for the lifecycle manager.
type Config struct {
	// JDClient is the client for connecting to the Job Distributor.
	JDClient client.ClientInterface
	// JobStore is the store for persisting job specs.
	JobStore store.StoreInterface
	// Runner is the job runner that handles job-specific logic.
	Runner JobRunner
	// Logger is the logger for the lifecycle manager.
	Logger logger.Logger
	// Metrics records proposal outcomes. Defaults to a no-op when nil.
	Metrics Metrics
	// OnConnectHook is an optional function called each time the JD connection is established.
	// A non-nil error is logged as a warning but does not prevent job processing.
	OnConnectHook func(ctx context.Context) error
}

// Manager manages the job lifecycle for JD-connected services.
// It handles:
// - Connecting to JD and staying connected
// - Loading cached jobs on startup
// - Receiving and processing job proposals
// - Handling job deletions and revocations
// - Persisting jobs for restart recovery.
type Manager struct {
	services.StateMachine

	jdClient      client.ClientInterface
	jobStore      store.StoreInterface
	runner        JobRunner
	lggr          logger.Logger
	metrics       Metrics
	onConnectHook func(ctx context.Context) error

	// Control-plane persistence/JD calls should stay short, but starting an application can include
	// database setup and chain RPC initialization. Keeping separate budgets prevents those startup
	// operations from inheriting a context already consumed by proposal bookkeeping.
	controlPlaneTimeout time.Duration
	jobStartTimeout     time.Duration

	mu            sync.Mutex
	state         State
	currentJob    *store.Job
	pendingJob    *store.Job // set when a proposal was saved but StartJob has not succeeded yet
	shutdownCh    services.StopChan
	wg            sync.WaitGroup
	jdConnectedCh chan struct{}      // buffered 1; sent when async Connect succeeds
	connectCancel context.CancelFunc // cancels the connect goroutine's context when Stop() is called
}

// NewManager creates a new job lifecycle manager.
// Returns an error if any required config field is nil.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.JDClient == nil {
		return nil, errors.New("JD client is required")
	}
	if cfg.JobStore == nil {
		return nil, errors.New("job store is required")
	}
	if cfg.Runner == nil {
		return nil, errors.New("runner is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = noopMetrics{}
	}
	return &Manager{
		jdClient:            cfg.JDClient,
		jobStore:            cfg.JobStore,
		runner:              cfg.Runner,
		lggr:                logger.With(cfg.Logger, "component", "JobLifecycleManager"),
		metrics:             metrics,
		onConnectHook:       cfg.OnConnectHook,
		controlPlaneTimeout: controlPlaneTimeout,
		jobStartTimeout:     defaultJobStartTimeout,
		state:               StateWaitingForJob,
		shutdownCh:          make(services.StopChan),
		jdConnectedCh:       make(chan struct{}, 1),
	}, nil
}

// Start starts the lifecycle manager.
// It performs the following:
// 1. Loads any cached job from the database
// 2. If a cached approved job exists, starts it immediately
// 3. If a cached pending job exists, defers start until JD reconnects
// 4. Connects to JD (even if there's a cached job, to receive updates)
// 5. Kicks off the event loop in a goroutine to handle proposals, deletions, and shutdown.
func (m *Manager) Start(ctx context.Context) error {
	return m.StartOnce("lifecycle.Manager", func() error {
		m.lggr.Infow("Starting job lifecycle manager")

		// 1. Load cached job if exists
		cachedJob, err := m.jobStore.LoadJob(ctx)
		if err != nil && !errors.Is(err, store.ErrNoJob) {
			return fmt.Errorf("failed to load cached job: %w", err)
		}

		// 2/3. Handle cached job based on its status
		if cachedJob != nil {
			switch cachedJob.Status {
			case store.JobStatusApproved, "": // empty = pre-status file, treat as approved
				m.lggr.Infow("Found approved cached job, starting immediately",
					"proposalID", cachedJob.ProposalID,
					"version", cachedJob.Version,
				)

				if err := m.runner.StartJob(ctx, cachedJob.Spec); err != nil {
					return fmt.Errorf("failed to start cached job: %w", err)
				}

				m.mu.Lock()
				m.state = StateRunning
				m.currentJob = cachedJob
				m.mu.Unlock()

				m.lggr.Infow("Cached job started successfully")

			case store.JobStatusPending:
				// A previous run saved the proposal but crashed before StartJob succeeded.
				// Defer the start until JD reconnects so we can call ApproveJob afterward.
				m.lggr.Infow("Found pending cached job, will retry after JD connects",
					"proposalID", cachedJob.ProposalID,
					"version", cachedJob.Version,
				)
				m.mu.Lock()
				m.pendingJob = cachedJob
				m.mu.Unlock()
			}
		}

		// 4. Connect to JD asynchronously (context only canceled when Manager is Stopped)
		m.lggr.Infow("Connecting to Job Distributor (async)")
		connectCtx, connectCancel := context.WithCancel(context.Background())
		m.mu.Lock()
		m.connectCancel = connectCancel
		m.mu.Unlock()

		m.wg.Go(func() {
			if err := m.jdClient.Connect(connectCtx); err != nil {
				if connectCtx.Err() == nil {
					m.lggr.Warnw("Failed to connect to JD", "error", err)
				}
				return
			}
			select {
			case m.jdConnectedCh <- struct{}{}:
			default:
				// event loop may have already exited; don't block
			}
		})

		// 5. Event loop
		m.wg.Go(func() {
			m.eventLoop()
		})

		return nil
	})
}

// eventLoop handles incoming events from JD and shutdown signals.
func (m *Manager) eventLoop() {
	m.lggr.Infow("Entering event loop", "state", m.GetState().String())

	for {
		select {
		case <-m.jdConnectedCh:
			m.lggr.Infow("Connected to Job Distributor")
			if m.onConnectHook != nil {
				hookCtx, hookCancel := context.WithTimeout(context.Background(), m.controlPlaneTimeout)
				if err := m.onConnectHook(hookCtx); err != nil {
					m.lggr.Warnw("OnConnectHook failed", "error", err)
				}
				hookCancel()
			}
			m.mu.Lock()
			pending := m.pendingJob
			m.mu.Unlock()
			if pending != nil {
				if err := m.retryPendingJob(pending); err != nil {
					m.lggr.Errorw("Failed to retry pending job after JD connect", "error", err,
						"proposalID", pending.ProposalID)
				}
			}

		case proposal := <-m.jdClient.JobProposalCh():
			if err := m.handleProposal(proposal); err != nil {
				m.lggr.Errorw("Failed to handle job proposal", "error", err, "proposalID", proposal.Id)
				// Don't return error - continue processing events
			}

		case deleteReq := <-m.jdClient.DeleteJobCh():
			if err := m.handleDelete(deleteReq); err != nil {
				m.lggr.Errorw("Failed to handle delete request", "error", err, "id", deleteReq.Id)
				// Don't return error - continue processing events
			}

		case revokeReq := <-m.jdClient.RevokeJobCh():
			// Revoke is only relevant for pending proposals that haven't been approved yet.
			// Since we auto-approve immediately, this is mostly a no-op.
			m.lggr.Infow("Received revoke request (ignored - we auto-approve)", "id", revokeReq.Id)

		case <-m.shutdownCh:
			m.lggr.Infow("Shutdown signal received")
			if err := m.shutdown(); err != nil {
				m.lggr.Errorw("Failed to shutdown job lifecycle manager", "error", err)
			}
			return
		}
	}
}

// handleProposal processes a new job proposal from JD.
// Order: validate replacement → persist pending → stop old job → start new job →
// mark approved → approve with JD. Validation is optional: runners that implement only
// JobRunner keep the existing stop-then-start flow.
//
// On StartJob failure with no prior job: the pending store record survives for restart recovery.
// On validation failure during a replacement: the old job remains running and the proposal is not
// persisted.
// On StopJob or StartJob failure during a replacement: the pending record is deleted and the old
// job is restarted from the in-memory snapshot so the job keeps running.
func (m *Manager) handleProposal(proposal *pb.ProposeJobRequest) (retErr error) {
	m.lggr.Infow("Handling job proposal",
		"proposalID", proposal.Id,
		"version", proposal.Version,
		"currentState", m.GetState().String(),
	)

	m.mu.Lock()
	// wasRunning indicates whether a job was already running when this proposal
	// arrived. This flag is also used as the "replacement" metric label.
	wasRunning := m.state == StateRunning
	currentJob := m.currentJob // snapshot for fallback; non-nil when wasRunning
	m.mu.Unlock()

	metricsCtx := context.Background()
	defer func() {
		result := resultSuccess
		if retErr != nil {
			result = resultError
		}
		m.metrics.IncProposal(metricsCtx, result, wasRunning)
	}()

	if wasRunning {
		// Reject invalid application config while the old job is still serving. Validation is
		// deliberately side-effect free, so it runs before the proposal is persisted and needs
		// no rollback. Runtime resources are built by StartJob only after cutover.
		if err := m.validateReplacement(proposal.Spec); err != nil {
			m.metrics.IncStepError(metricsCtx, stepValidateReplacement, true)
			rejectCtx, rejectCancel := m.shutdownCh.CtxWithTimeout(m.controlPlaneTimeout)
			defer rejectCancel()
			if rejectErr := m.jdClient.RejectJob(rejectCtx, proposal.Id, proposal.Version); rejectErr != nil {
				m.lggr.Warnw("Failed to reject job with JD after validation failure",
					"error", rejectErr,
					"proposalID", proposal.Id,
				)
				m.metrics.IncStepError(metricsCtx, stepRejectJob, true)
			} else {
				m.lggr.Infow("Rejected job with JD after validation failure",
					"proposalID", proposal.Id,
				)
			}
			return fmt.Errorf("failed to validate replacement job: %w", err)
		}
	}

	controlCtx, controlCancel := context.WithTimeout(context.Background(), m.controlPlaneTimeout)
	defer controlCancel()

	// Persist the proposal as pending BEFORE attempting StartJob. This ensures
	// that a crash between here and AcceptPendingJob leaves a recoverable record.
	// SavePendingJob only removes the previous pending row; any approved (old) row is preserved.
	// Persistence failure is non-fatal: the replacement continues from the in-memory proposal,
	// and only crash recovery is degraded until JD re-proposes.
	if err := m.jobStore.SavePendingJob(controlCtx, proposal.Id, proposal.Version, proposal.Spec); err != nil {
		m.lggr.Warnw("Failed to persist pending proposal", "error", err)
		m.metrics.IncStepError(metricsCtx, stepSavePending, wasRunning)
	} else {
		m.lggr.Infow("Proposal persisted as pending", "proposalID", proposal.Id)
	}

	if wasRunning {
		m.lggr.Infow("Stopping current job for replacement")
		if err := m.runner.StopJob(controlCtx); err != nil {
			m.metrics.IncStepError(metricsCtx, stepStopJob, true)
			return m.rollbackReplacement(proposal.Id, fmt.Errorf("failed to stop current job: %w", err), currentJob)
		}
	}

	// Starting a job can include database setup and sequential RPC client initialization. Give it a
	// fresh, dedicated budget instead of whatever remains of the control-plane timeout above.
	if err := m.startJob(proposal.Spec); err != nil {
		rejectCtx, rejectCancel := m.shutdownCh.CtxWithTimeout(m.controlPlaneTimeout)
		defer rejectCancel()
		if rejectErr := m.jdClient.RejectJob(rejectCtx, proposal.Id, proposal.Version); rejectErr != nil {
			m.lggr.Warnw("Failed to reject job with JD after StartJob failure",
				"error", rejectErr,
				"proposalID", proposal.Id,
			)
			m.metrics.IncStepError(metricsCtx, stepRejectJob, wasRunning)
		} else {
			m.lggr.Infow("Rejected job with JD after StartJob failure",
				"proposalID", proposal.Id,
			)
		}

		if wasRunning {
			m.metrics.IncStepError(metricsCtx, stepStartReplacement, wasRunning)
			return m.rollbackReplacement(proposal.Id, fmt.Errorf("failed to start replacement job: %w", err), currentJob)
		}
		// No old job to fall back to: leave pending record for restart recovery.
		m.metrics.IncStepError(metricsCtx, stepStartJob, wasRunning)
		m.mu.Lock()
		m.state = StateWaitingForJob
		m.currentJob = nil
		// Keep pendingJob set so the retry fires on the next JD reconnect
		// within this same process run (if JD reconnects).
		m.pendingJob = &store.Job{
			ProposalID: proposal.Id,
			Version:    proposal.Version,
			Spec:       proposal.Spec,
			Status:     store.JobStatusPending,
		}
		m.mu.Unlock()
		return fmt.Errorf("failed to start new job: %w", err)
	}

	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), m.controlPlaneTimeout)
	defer finalizeCancel()

	// StartJob succeeded - promote the pending record to approved.
	if promoted, err := m.jobStore.AcceptPendingJob(finalizeCtx); err != nil {
		m.lggr.Warnw("Failed to accept pending job in store", "error", err)
		m.metrics.IncStepError(metricsCtx, stepAcceptPending, wasRunning)
		// Continue anyway - the job is running. The store record stays 'pending', so the
		// next restart will retry via the pending recovery path.
	} else if !promoted {
		m.lggr.Warnw("AcceptPendingJob reported no pending row — store may be inconsistent")
		m.metrics.IncStepError(metricsCtx, stepAcceptPending, wasRunning)
	}

	// Update in-memory state
	m.mu.Lock()
	m.state = StateRunning
	m.currentJob = &store.Job{
		ProposalID: proposal.Id,
		Version:    proposal.Version,
		Spec:       proposal.Spec,
		Status:     store.JobStatusApproved,
	}
	m.pendingJob = nil
	m.mu.Unlock()

	// Approve the job with JD
	if err := m.jdClient.ApproveJob(finalizeCtx, proposal.Id, proposal.Version); err != nil {
		m.lggr.Warnw("Failed to approve job with JD", "error", err)
		m.metrics.IncStepError(metricsCtx, stepApproveJob, wasRunning)
		// Continue anyway - job is running.
	}

	m.lggr.Infow("Job proposal handled successfully",
		"proposalID", proposal.Id,
		"newState", m.GetState().String(),
	)

	return nil
}

// startJob gives application startup its own deadline. Proposal persistence and JD acknowledgements
// use the shorter control-plane budget and must not consume time needed for service initialization.
// Closing shutdownCh cancels an in-flight start so Manager.Stop does not wait for the full deadline.
func (m *Manager) startJob(spec string) error {
	ctx, cancel := m.shutdownCh.CtxWithTimeout(m.jobStartTimeout)
	defer cancel()
	return m.runner.StartJob(ctx, spec)
}

// validateReplacement asks an optional ValidatingJobRunner to preflight a replacement while the
// current job is still active. Validation is side-effect-free config checking, so it gets the
// control-plane budget rather than the job-start one.
func (m *Manager) validateReplacement(spec string) error {
	runner, ok := m.runner.(ValidatingJobRunner)
	if !ok {
		return nil
	}
	ctx, cancel := m.shutdownCh.CtxWithTimeout(m.controlPlaneTimeout)
	defer cancel()
	return runner.ValidateJob(ctx, spec)
}

// rollbackReplacement is called after replacement cutover has been attempted. StopJob may return
// an error after partially stopping the service, so both stop and start failures use the same
// recovery: remove the pending record and restart the old spec.
func (m *Manager) rollbackReplacement(newProposalID string, cause error, oldJob *store.Job) error {
	ctx, cancel := m.shutdownCh.CtxWithTimeout(m.controlPlaneTimeout)
	defer cancel()
	metricsCtx := context.Background()
	var errs error
	if delErr := m.jobStore.DeletePendingJob(ctx); delErr != nil {
		m.lggr.Warnw("Failed to remove pending record during rollback", "error", delErr)
		m.metrics.IncStepError(metricsCtx, stepRollbackDeletePending, true)
		errs = errors.Join(errs, fmt.Errorf("delete pending replacement: %w", delErr))
	}
	m.lggr.Infow("Restarting previous job after replacement failure",
		"newProposalID", newProposalID,
		"fallbackProposalID", oldJob.ProposalID,
	)
	if restartErr := m.startJob(oldJob.Spec); restartErr != nil {
		m.lggr.Errorw("Failed to restart previous job after replacement failure", "error", restartErr)
		m.metrics.IncStepError(metricsCtx, stepRollbackRestart, true)
		m.mu.Lock()
		m.state = StateWaitingForJob
		m.currentJob = nil
		m.mu.Unlock()
		errs = errors.Join(errs, fmt.Errorf("restart previous job: %w", restartErr))
	}
	return errors.Join(cause, errs)
}

// retryPendingJob attempts to start the pending job after JD has reconnected.
// On success it marks the store record approved, updates in-memory state, and calls ApproveJob.
// On failure the pending record in the store is preserved for the next restart.
func (m *Manager) retryPendingJob(job *store.Job) (retErr error) {
	m.lggr.Infow("Retrying pending job after JD connect",
		"proposalID", job.ProposalID,
		"version", job.Version,
	)
	metricsCtx := context.Background()
	defer func() {
		result := resultSuccess
		if retErr != nil {
			result = resultError
		}
		m.metrics.IncProposal(metricsCtx, result, false)
	}()

	if err := m.startJob(job.Spec); err != nil {
		m.metrics.IncStepError(metricsCtx, stepStartJob, false)
		return fmt.Errorf("failed to start pending job: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.controlPlaneTimeout)
	defer cancel()

	if promoted, err := m.jobStore.AcceptPendingJob(ctx); err != nil {
		m.lggr.Warnw("Failed to accept pending job in store", "error", err)
		m.metrics.IncStepError(metricsCtx, stepAcceptPending, false)
	} else if !promoted {
		m.lggr.Warnw("AcceptPendingJob reported no pending row — store may be inconsistent")
		m.metrics.IncStepError(metricsCtx, stepAcceptPending, false)
	}

	m.mu.Lock()
	m.state = StateRunning
	m.currentJob = &store.Job{
		ProposalID: job.ProposalID,
		Version:    job.Version,
		Spec:       job.Spec,
		Status:     store.JobStatusApproved,
	}
	m.pendingJob = nil
	m.mu.Unlock()

	if err := m.jdClient.ApproveJob(ctx, job.ProposalID, job.Version); err != nil {
		m.lggr.Warnw("Failed to approve pending job with JD", "error", err)
		m.metrics.IncStepError(metricsCtx, stepApproveJob, false)
	}

	m.lggr.Infow("Pending job started successfully",
		"proposalID", job.ProposalID,
		"newState", m.GetState().String(),
	)

	return nil
}

// handleDelete processes a job deletion request from JD.
func (m *Manager) handleDelete(req *pb.DeleteJobRequest) error {
	m.lggr.Infow("Handling delete request", "id", req.Id, "currentState", m.GetState().String())

	ctx, cancel := context.WithTimeout(context.Background(), m.controlPlaneTimeout)
	defer cancel()

	m.mu.Lock()
	wasRunning := m.state == StateRunning
	currentJob := m.currentJob
	pendingJob := m.pendingJob
	m.mu.Unlock()

	// Handle deletion of a pending (not yet running) job
	if !wasRunning {
		if pendingJob != nil && pendingJob.ProposalID == req.Id {
			m.lggr.Infow("Deleting pending job", "id", req.Id)
			m.mu.Lock()
			m.pendingJob = nil
			m.mu.Unlock()
			if err := m.jobStore.DeleteAllJobs(ctx); err != nil {
				m.lggr.Warnw("Failed to clear pending job", "error", err)
			}
			return nil
		}
		m.lggr.Infow("No job running, ignoring delete request")
		return nil
	}

	// Check if the delete is for our current running job
	if currentJob != nil && currentJob.ProposalID != req.Id {
		m.lggr.Infow("Delete request is for different job, ignoring",
			"requestID", req.Id,
			"currentJobID", currentJob.ProposalID,
		)
		return nil
	}

	// Stop the current job
	if err := m.runner.StopJob(ctx); err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
	}

	// Clear persisted job
	if err := m.jobStore.DeleteAllJobs(ctx); err != nil {
		m.lggr.Warnw("Failed to clear persisted job", "error", err)
		// Continue anyway
	}

	// Update state
	m.mu.Lock()
	m.state = StateWaitingForJob
	m.currentJob = nil
	m.mu.Unlock()

	m.lggr.Infow("Job deleted, waiting for new proposal", "id", req.Id)

	return nil
}

// shutdown performs graceful shutdown of the manager.
func (m *Manager) shutdown() error {
	m.lggr.Infow("Shutting down job lifecycle manager")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var errs error

	// Stop current job if running
	m.mu.Lock()
	wasRunning := m.state == StateRunning
	m.mu.Unlock()

	if wasRunning {
		m.lggr.Infow("Stopping current job")
		if err := m.runner.StopJob(ctx); err != nil {
			m.lggr.Warnw("Error stopping job during shutdown", "error", err)
			errs = errors.Join(errs, err)
		}
	}

	// Close JD connection
	if err := m.jdClient.Close(); err != nil {
		m.lggr.Warnw("Error closing JD connection", "error", err)
		errs = errors.Join(errs, err)
	}

	m.lggr.Infow("Job lifecycle manager shutdown complete")
	return errs
}

// Stop signals the manager to stop.
// This is safe to call from any goroutine.
func (m *Manager) Stop() error {
	return m.StopOnce("lifecycle.Manager", func() error {
		m.mu.Lock()
		connectCancel := m.connectCancel
		m.connectCancel = nil
		m.mu.Unlock()
		if connectCancel != nil {
			connectCancel()
		}
		close(m.shutdownCh)
		m.wg.Wait()
		return nil
	})
}

// GetState returns the current state of the manager.
func (m *Manager) GetState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}
