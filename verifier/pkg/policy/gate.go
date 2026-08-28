package policy

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// maxConcurrentEvaluations bounds how many policy calls a single batch makes at once. The task
// verifier hands the gate a batch of up to StorageBatchSize (50) messages every poll, and firing
// all of them at an operator's endpoint simultaneously is a poor default. Verification stays
// well inside the two-minute job lock even at this width with the default five-second timeout.
const maxConcurrentEvaluations = 8

// GatedVerifier wraps a vtypes.Verifier with the policy hook. Each message is evaluated against
// the operator's endpoint first; only a PASS reaches the wrapped verifier, so signing and the
// signed payload are untouched by the hook.
//
// The wrapper is deliberately generic over vtypes.Verifier rather than built into the committee
// verifier: the same gate composes with any verifier implementation without duplicating the
// endpoint call, the retry classification, or the drop accounting.
type GatedVerifier struct {
	inner      vtypes.Verifier
	checker    Checker
	lggr       logger.Logger
	monitoring vtypes.Monitoring
	verifierID string
	retryDelay time.Duration
}

// NewGatedVerifier wraps inner with the policy gate. retryDelay is how long a message waits
// before the endpoint is called again after an endpoint error.
func NewGatedVerifier(
	lggr logger.Logger,
	verifierID string,
	inner vtypes.Verifier,
	checker Checker,
	verifierMonitoring vtypes.Monitoring,
	retryDelay time.Duration,
) (*GatedVerifier, error) {
	switch {
	case inner == nil:
		return nil, errors.New("inner verifier is required")
	case checker == nil:
		return nil, errors.New("policy checker is required")
	case lggr == nil:
		return nil, errors.New("logger is required")
	case verifierMonitoring == nil:
		return nil, errors.New("monitoring is required")
	}
	if retryDelay <= 0 {
		retryDelay = DefaultRetryDelay
	}

	return &GatedVerifier{
		inner:      inner,
		checker:    checker,
		lggr:       logger.With(lggr, "component", "PolicyGatedVerifier"),
		monitoring: verifierMonitoring,
		verifierID: verifierID,
		retryDelay: retryDelay,
	}, nil
}

// VerifyMessages evaluates every task against the policy endpoint and forwards the passing ones
// to the wrapped verifier. Every task in produces exactly one result out, which is what the task
// verifier needs to map results back to queue jobs.
func (g *GatedVerifier) VerifyMessages(ctx context.Context, tasks []vtypes.VerificationTask) []vtypes.VerificationResult {
	if len(tasks) == 0 {
		return nil
	}

	verdicts := g.evaluateAll(ctx, tasks)

	results := make([]vtypes.VerificationResult, 0, len(tasks))
	passed := make([]vtypes.VerificationTask, 0, len(tasks))

	for i, task := range tasks {
		v := verdicts[i]
		switch {
		case v.err != nil:
			results = append(results, vtypes.VerificationResult{Error: g.endpointErrorResult(ctx, task, v.err)})
		case v.verdict.Decision == DecisionFail:
			results = append(results, vtypes.VerificationResult{Error: g.rejectedResult(ctx, task, v.verdict.Reason)})
		default:
			g.messageMetrics(task.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStagePolicy,
				monitoring.MessageTransitionOutcomePolicyPassed,
				monitoring.MessageTransitionReasonNone)
			passed = append(passed, task)
		}
	}

	if len(passed) > 0 {
		results = append(results, g.inner.VerifyMessages(ctx, passed)...)
	}

	return results
}

// evaluation is one endpoint call's outcome, index-aligned with the batch.
type evaluation struct {
	verdict Verdict
	err     error
}

func (g *GatedVerifier) evaluateAll(ctx context.Context, tasks []vtypes.VerificationTask) []evaluation {
	out := make([]evaluation, len(tasks))
	sem := make(chan struct{}, maxConcurrentEvaluations)

	var wg sync.WaitGroup
	for i := range tasks {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req := NewEvaluateRequest(g.verifierID, &tasks[index])
			verdict, err := g.checker.Evaluate(ctx, req)
			out[index] = evaluation{verdict: verdict, err: err}
		}(i)
	}
	wg.Wait()

	return out
}

// rejectedResult turns a FAIL into a permanent verification error. The task verifier fails the
// queue job, so the message is never signed, never written to an aggregator, and never
// auto-executed. Recovery is an operator replay: reschedule the archived job with the verifier
// CLI, or rewind the checkpoint as for a message dropped by a curse or a disablement rule.
func (g *GatedVerifier) rejectedResult(ctx context.Context, task vtypes.VerificationTask, reason string) *vtypes.VerificationError {
	g.messageMetrics(task.Message).IncrementMessageTransition(
		ctx,
		monitoring.MessageTransitionStagePolicy,
		monitoring.MessageTransitionOutcomePolicyRejected,
		monitoring.MessageTransitionReasonPolicyRejected)

	g.lggr.Warnw("Dropping task - policy hook returned FAIL",
		protocol.LogKeyMessageID, task.MessageID,
		protocol.LogKeySourceChain, task.Message.SourceChainSelector,
		protocol.LogKeyDestChain, task.Message.DestChainSelector,
		protocol.LogKeySeqNum, task.Message.SequenceNumber,
		"reason", reason,
	)

	err := fmt.Errorf("policy hook rejected message %s", task.MessageID)
	if reason != "" {
		err = fmt.Errorf("policy hook rejected message %s: %s", task.MessageID, reason)
	}
	verificationErr := vtypes.NewVerificationError(err, task)
	return &verificationErr
}

// endpointErrorResult turns an unknown verdict into a retryable verification error. An endpoint
// outage must never look like a rejection, so this path never drops the message: the task queue
// retries it for its full retry window.
func (g *GatedVerifier) endpointErrorResult(ctx context.Context, task vtypes.VerificationTask, cause error) *vtypes.VerificationError {
	g.messageMetrics(task.Message).IncrementMessageTransition(
		ctx,
		monitoring.MessageTransitionStagePolicy,
		monitoring.MessageTransitionOutcomePolicyUnavailable,
		monitoring.MessageTransitionReasonPolicyEndpointError)

	delay := g.retryDelayWithJitter()

	g.lggr.Warnw("Policy hook verdict unavailable, scheduling retry",
		protocol.LogTypeKey, protocol.LogTypeRetryableMessageFailure,
		protocol.LogKeyMessageID, task.MessageID,
		protocol.LogKeySourceChain, task.Message.SourceChainSelector,
		protocol.LogKeyDestChain, task.Message.DestChainSelector,
		"retryDelay", delay,
		"error", cause,
	)

	verificationErr := vtypes.NewRetriableVerificationError(cause, task, delay)
	return &verificationErr
}

// retryDelayWithJitter spreads a message's next attempt across [retryDelay/2, retryDelay*3/2].
// An outage stalls every message the verifier is holding at once, and a fixed delay would
// reschedule all of them on the same tick, so the whole backlog would arrive at the endpoint
// together every retryDelay for as long as the outage lasts. That is the worst shape to hand an
// endpoint that is already failing or rate-limiting, and the endpoint is the operator's to pay
// for. Spreading the retries does not reduce the total call volume, only its burstiness; backoff
// that grows with the attempt count needs the queue's attempt_count on the task and is tracked
// separately.
func (g *GatedVerifier) retryDelayWithJitter() time.Duration {
	half := int64(g.retryDelay / 2)
	if half <= 0 {
		return g.retryDelay
	}
	//nolint:gosec // G404: jitter spreads retry load, it is not a security decision.
	return g.retryDelay - time.Duration(half) + time.Duration(mrand.Int64N(2*half+1))
}

func (g *GatedVerifier) messageMetrics(message protocol.Message) vtypes.MetricLabeler {
	return g.monitoring.Metrics().With(
		"source_chain", message.SourceChainSelector.String(),
		"source_chain_name", message.SourceChainSelector.ChainName(),
		"dest_chain", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
		"verifier_id", g.verifierID,
	)
}

var _ vtypes.Verifier = (*GatedVerifier)(nil)

// WrapVerifier applies the policy hook to inner when the operator configured one. A nil config
// returns inner unchanged, so a verifier without a hook has no extra layer in its call path at
// all. Both the standalone and Chainlink-node constructors call this, which keeps the enable
// condition and the gate's construction in one place rather than duplicated per deployment mode.
func WrapVerifier(
	lggr logger.Logger,
	verifierID string,
	inner vtypes.Verifier,
	cfg *Config,
	verifierMonitoring vtypes.Monitoring,
) (vtypes.Verifier, error) {
	if cfg == nil {
		return inner, nil
	}

	checker, err := NewHTTPChecker(lggr, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy hook client: %w", err)
	}
	retryDelay, err := cfg.RetryDelayDuration()
	if err != nil {
		return nil, err
	}
	gated, err := NewGatedVerifier(lggr, verifierID, inner, checker, verifierMonitoring, retryDelay)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy gated verifier: %w", err)
	}

	lggr.Infow("Policy hook enabled",
		"endpoint", cfg.EndpointURL,
		"retryDelay", retryDelay,
	)

	return gated, nil
}
