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
	handleTimeout   = 10 * time.Second
	shutdownTimeout = 5 * time.Second
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

	jdClient client.ClientInterface
	jobStore store.StoreInterface
	runner   JobRunner
	lggr     logger.Logger

	mu            sync.Mutex
	state         State
	currentJob    *store.Job
	pendingJob    *store.Job // set when a proposal was saved but StartJob has not succeeded yet
	shutdownCh    chan struct{}
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
	return &Manager{
		jdClient:      cfg.JDClient,
		jobStore:      cfg.JobStore,
		runner:        cfg.Runner,
		lggr:          logger.With(cfg.Logger, "component", "JobLifecycleManager"),
		state:         StateWaitingForJob,
		shutdownCh:    make(chan struct{}),
		jdConnectedCh: make(chan struct{}, 1),
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
// Order: persist pending → stop old job → start new job → mark approved → approve with JD.
//
// On StartJob failure with no prior job: the pending store record survives for restart recovery.
// On StartJob failure during a replacement: the pending record is deleted and the old job is
// restarted from the in-memory snapshot so the job keeps running.
func (m *Manager) handleProposal(proposal *pb.ProposeJobRequest) error {
	m.lggr.Infow("Handling job proposal",
		"proposalID", proposal.Id,
		"version", proposal.Version,
		"currentState", m.GetState().String(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), handleTimeout)
	defer cancel()

	// Persist the proposal as pending BEFORE attempting StartJob. This ensures
	// that a crash between here and MarkJobApproved leaves a recoverable record.
	// SavePendingJob only removes the previous pending row; any approved (old) row is preserved.
	if err := m.jobStore.SavePendingJob(ctx, proposal.Id, proposal.Version, proposal.Spec); err != nil {
		// The job will need to be re-proposed after fixing the error (whatever it may be).
		m.lggr.Warnw("Failed to persist pending proposal", "error", err)
	} else {
		m.lggr.Infow("Proposal persisted as pending", "proposalID", proposal.Id)
	}

	m.mu.Lock()
	wasRunning := m.state == StateRunning
	currentJob := m.currentJob // snapshot for fallback; non-nil when wasRunning
	m.mu.Unlock()

	// If we have a running job, stop it first
	if wasRunning {
		m.lggr.Infow("Stopping current job for replacement")
		if err := m.runner.StopJob(ctx); err != nil {
			return fmt.Errorf("failed to stop current job: %w", err)
		}
	}

	// Start the new job
	if err := m.runner.StartJob(ctx, proposal.Spec); err != nil {
		if wasRunning {
			return m.rollbackReplacement(ctx, proposal.Id, err, currentJob)
		}
		// No old job to fall back to: leave pending record for restart recovery.
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

	// StartJob succeeded - promote the pending record to approved.
	if promoted, err := m.jobStore.AcceptPendingJob(ctx); err != nil {
		m.lggr.Warnw("Failed to accept pending job in store", "error", err)
		// Continue anyway - the job is running. The store record stays 'pending', so the
		// next restart will retry via the pending recovery path.
	} else if !promoted {
		m.lggr.Warnw("AcceptPendingJob reported no pending row — store may be inconsistent")
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
	if err := m.jdClient.ApproveJob(ctx, proposal.Id, proposal.Version); err != nil {
		m.lggr.Warnw("Failed to approve job with JD", "error", err)
		// Continue anyway - job is running.
	}

	m.lggr.Infow("Job proposal handled successfully",
		"proposalID", proposal.Id,
		"newState", m.GetState().String(),
	)

	return nil
}

// rollbackReplacement is called when StartJob fails during a proposal replacement.
// It removes the pending store record and restarts the old job to keep the job running.
func (m *Manager) rollbackReplacement(ctx context.Context, newProposalID string, startErr error, oldJob *store.Job) error {
	if delErr := m.jobStore.DeletePendingJob(ctx); delErr != nil {
		m.lggr.Warnw("Failed to remove pending record during rollback", "error", delErr)
	}
	m.lggr.Infow("Restarting previous job after replacement failure",
		"newProposalID", newProposalID,
		"fallbackProposalID", oldJob.ProposalID,
	)
	if restartErr := m.runner.StartJob(ctx, oldJob.Spec); restartErr != nil {
		m.lggr.Errorw("Failed to restart previous job after replacement failure", "error", restartErr)
		m.mu.Lock()
		m.state = StateWaitingForJob
		m.currentJob = nil
		m.mu.Unlock()
	}
	return fmt.Errorf("failed to start replacement job: %w", startErr)
}

// retryPendingJob attempts to start the pending job after JD has reconnected.
// On success it marks the store record approved, updates in-memory state, and calls ApproveJob.
// On failure the pending record in the store is preserved for the next restart.
func (m *Manager) retryPendingJob(job *store.Job) error {
	m.lggr.Infow("Retrying pending job after JD connect",
		"proposalID", job.ProposalID,
		"version", job.Version,
	)

	ctx, cancel := context.WithTimeout(context.Background(), handleTimeout)
	defer cancel()

	if err := m.runner.StartJob(ctx, job.Spec); err != nil {
		return fmt.Errorf("failed to start pending job: %w", err)
	}

	if promoted, err := m.jobStore.AcceptPendingJob(ctx); err != nil {
		m.lggr.Warnw("Failed to accept pending job in store", "error", err)
	} else if !promoted {
		m.lggr.Warnw("AcceptPendingJob reported no pending row — store may be inconsistent")
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

	ctx, cancel := context.WithTimeout(context.Background(), handleTimeout)
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
