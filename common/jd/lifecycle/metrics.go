package lifecycle

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

const (
	resultSuccess = "success"
	resultError   = "error"

	// Step labels for jd_lifecycle_proposal_step_errors_total. Each names a
	// discrete step in handleProposal/retryPendingJob that can fail. A single
	// proposal may record several of these
	stepSavePending           = "save_pending"
	stepStopJob               = "stop_job"
	stepStartJob              = "start_job"
	stepStartReplacement      = "start_replacement"
	stepRollbackDeletePending = "rollback_delete_pending"
	stepRollbackRestart       = "rollback_restart"
	stepAcceptPending         = "accept_pending"
	stepApproveJob            = "approve_job"
)

// Metrics records JD lifecycle proposal outcomes.
type Metrics interface {
	// IncProposal records the terminal outcome of a proposal exactly once.
	// result is resultSuccess when a job is running at the end of the flow and
	// resultError when the proposal aborted without a running job.
	IncProposal(ctx context.Context, result string, replacement bool)
	// IncStepError records a single failed step within a proposal. It may be
	// called multiple times per proposal (once per failing step) and is
	// independent of the terminal outcome recorded by IncProposal.
	IncStepError(ctx context.Context, step string, replacement bool)
}

type otelMetrics struct {
	proposalTotal   metric.Int64Counter
	stepErrorsTotal metric.Int64Counter
}

func InitMetrics() (Metrics, error) {
	meter := beholder.GetMeter()
	proposalTotal, err := meter.Int64Counter(
		"jd_lifecycle_proposal_total",
		metric.WithDescription("JD lifecycle job proposal outcomes"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register jd_lifecycle_proposal_total: %w", err)
	}
	stepErrorsTotal, err := meter.Int64Counter(
		"jd_lifecycle_proposal_step_errors_total",
		metric.WithDescription("JD lifecycle proposal step failures"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register jd_lifecycle_proposal_step_errors_total: %w", err)
	}
	return &otelMetrics{proposalTotal: proposalTotal, stepErrorsTotal: stepErrorsTotal}, nil
}

func (m *otelMetrics) IncProposal(ctx context.Context, result string, replacement bool) {
	m.proposalTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.Bool("replacement", replacement),
	))
}

func (m *otelMetrics) IncStepError(ctx context.Context, step string, replacement bool) {
	m.stepErrorsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("step", step),
		attribute.Bool("replacement", replacement),
	))
}

type noopMetrics struct{}

func (noopMetrics) IncProposal(context.Context, string, bool)  {}
func (noopMetrics) IncStepError(context.Context, string, bool) {}
