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
// 2. If a cached job exists, starts it immediately
// 3. Connects to JD (even if there's a cached job, to receive updates)
// 4. Kicks off the event loop in a goroutine to handle proposals, deletions, and shutdown.
func (m *Manager) Start(ctx context.Context) error {
	return m.StartOnce("lifecycle.Manager", func() error {
		m.lggr.Infow("Starting job lifecycle manager")

		// 1. Load cached job if exists
		cachedJob, err := m.jobStore.LoadJob(ctx)
		if err != nil && !errors.Is(err, store.ErrNoJob) {
			return fmt.Errorf("failed to load cached job: %w", err)
		}

		// 2. If cached job exists, start it
		if cachedJob != nil {
			m.lggr.Infow("Found cached job, starting immediately",
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
		}

		// 3. Connect to JD asynchronously (context only canceled when Manager is Stopped)
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

		// 4. Event loop
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
func (m *Manager) handleProposal(proposal *pb.ProposeJobRequest) error {
	m.lggr.Infow("Handling job proposal",
		"proposalID", proposal.Id,
		"version", proposal.Version,
		"currentState", m.GetState().String(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m.mu.Lock()
	wasRunning := m.state == StateRunning
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
		// TODO: whats the best way to recover from this? Will JD have to re-propose the job?
		m.mu.Lock()
		m.state = StateWaitingForJob
		m.currentJob = nil
		m.mu.Unlock()
		return fmt.Errorf("failed to start new job: %w", err)
	}

	// Persist the job
	if err := m.jobStore.SaveJob(ctx, proposal.Id, proposal.Version, proposal.Spec); err != nil {
		m.lggr.Warnw("Failed to persist job", "error", err)
		// Continue anyway - job is running in memory.
		// Will have to re-propose to this operator if the app crashes / restarts.
	} else {
		m.lggr.Infow("Job persisted for restart recovery", "proposalID", proposal.Id)
	}

	// Update state
	m.mu.Lock()
	m.state = StateRunning
	m.currentJob = &store.Job{
		ProposalID: proposal.Id,
		Version:    proposal.Version,
		Spec:       proposal.Spec,
	}
	m.mu.Unlock()

	// Approve the job with JD
	if err := m.jdClient.ApproveJob(ctx, proposal.Id, proposal.Version); err != nil {
		m.lggr.Warnw("Failed to approve job with JD", "error", err)
		// Continue anyway - job is running.
		// TODO: how will this look like on the JD side?
	}

	m.lggr.Infow("Job proposal handled successfully",
		"proposalID", proposal.Id,
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
	m.mu.Unlock()

	// Only process if we have a running job
	if !wasRunning {
		m.lggr.Infow("No job running, ignoring delete request")
		return nil
	}

	// Check if the delete is for our current job
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
	if err := m.jobStore.DeleteJob(ctx); err != nil {
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
