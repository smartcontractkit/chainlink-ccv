package policy

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// maxConcurrentEvaluations bounds how many policy calls a single batch makes at once. The task
// verifier hands the gate a batch of up to StorageBatchSize (50) messages every poll, and firing
// all of them at an operator's endpoint simultaneously is a poor default. Verification stays
// well inside the two-minute job lock even at this width with the default five-second timeout.
const maxConcurrentEvaluations = 8

// GatedVerifier wraps a vtypes.Verifier with the policy hook. Only a PASS reaches the wrapped
// verifier's signing path, so signing and the signed payload are untouched by the hook.
//
// The hook is the last check before signing, which is the order the operator is promised: a
// message reaching the endpoint has already cleared finality, the curse and message-disablement
// checks at admission, and the wrapped verifier's own checks on the task. The last of those is
// the reason for precheck. The gate cannot run the wrapped verifier's checks itself (the commit
// verifier's config package imports this one, so the dependency only goes one way), so it asks
// the wrapped verifier through the optional vtypes.TaskValidator interface instead. A task the
// wrapped verifier already rejects is forwarded without an endpoint call, and comes back with
// the wrapped verifier's own error.
//
// The wrapper is deliberately generic over vtypes.Verifier rather than built into the committee
// verifier: the same gate composes with any verifier implementation without duplicating the
// endpoint call, the retry classification, or the drop accounting. A wrapped verifier that does
// not implement vtypes.TaskValidator simply gets an endpoint call for every task.
type GatedVerifier struct {
	inner      vtypes.Verifier
	precheck   vtypes.TaskValidator
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

	gate := &GatedVerifier{
		inner:      inner,
		checker:    checker,
		lggr:       logger.With(lggr, "component", "PolicyGatedVerifier"),
		monitoring: verifierMonitoring,
		verifierID: verifierID,
		retryDelay: retryDelay,
	}
	// Optional: only verifiers that can reject a task without signing it provide this.
	if validator, ok := inner.(vtypes.TaskValidator); ok {
		gate.precheck = validator
	}

	return gate, nil
}

// VerifyMessages evaluates the tasks the wrapped verifier would sign against the policy endpoint
// and forwards the passing ones. Every task in produces exactly one result out, which is what the
// task verifier needs to map results back to queue jobs. Results come back in a different order
// than they went in; the task verifier indexes them by message ID, not by position.
func (g *GatedVerifier) VerifyMessages(ctx context.Context, tasks []vtypes.VerificationTask) []vtypes.VerificationResult {
	if len(tasks) == 0 {
		return nil
	}

	evaluate, invalid := g.partition(ctx, tasks)
	verdicts := g.evaluateAll(ctx, evaluate)

	results := make([]vtypes.VerificationResult, 0, len(tasks))
	forward := append(make([]vtypes.VerificationTask, 0, len(tasks)), invalid...)

	for i, task := range evaluate {
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
			forward = append(forward, task)
		}
	}

	if len(forward) > 0 {
		results = append(results, g.inner.VerifyMessages(ctx, forward)...)
	}

	return results
}

// partition splits a batch into the tasks that need a verdict and the tasks the wrapped verifier
// has already said it will reject.
//
// The second group is still forwarded to the wrapped verifier, and that is the point: the gate
// has to return one result per task, and the result an invalid task deserves is the verifier's
// own error, not one the gate made up. So it lets the verifier reject the task itself, which
// produces the same error string, the same retryable-or-not classification, and the same metrics
// an ungated verifier would have produced for it. The verifier is going to redo the validation,
// which is cheap; what is skipped is the endpoint call, which is not. Synthesizing the rejection
// here instead would save nothing and would give the gate a second copy of the verifier's error
// handling to keep in step.
//
// Skipping the call is safe in only one direction, and this is the direction: a task the wrapped
// verifier rejects can never be signed, whatever the endpoint would have said about it. The
// reverse, a precheck stricter than the verifier, would skip the endpoint on a task that then
// gets signed, which is why vtypes.TaskValidator requires the two to be one implementation.
func (g *GatedVerifier) partition(ctx context.Context, tasks []vtypes.VerificationTask) (evaluate, invalid []vtypes.VerificationTask) {
	if g.precheck == nil {
		return tasks, nil
	}

	evaluate = make([]vtypes.VerificationTask, 0, len(tasks))
	for i := range tasks {
		err := g.precheck.ValidateTask(&tasks[i])
		if err == nil {
			evaluate = append(evaluate, tasks[i])
			continue
		}
		g.recordSkipped(ctx, tasks[i], err)
		invalid = append(invalid, tasks[i])
	}

	return evaluate, invalid
}

// recordSkipped accounts for a task that reached the policy stage without an endpoint call, so
// the stage's counters still add up to the messages that entered it.
func (g *GatedVerifier) recordSkipped(ctx context.Context, task vtypes.VerificationTask, cause error) {
	g.messageMetrics(task.Message).IncrementMessageTransition(
		ctx,
		monitoring.MessageTransitionStagePolicy,
		monitoring.MessageTransitionOutcomePolicySkipped,
		monitoring.MessageTransitionReasonTaskInvalid)

	g.lggr.Debugw("Skipping policy hook - the verifier rejects this task before signing",
		protocol.LogKeyMessageID, task.MessageID,
		protocol.LogKeySourceChain, task.Message.SourceChainSelector,
		protocol.LogKeyDestChain, task.Message.DestChainSelector,
		"error", cause,
	)
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
	// Bounded here rather than trusted from the Checker. HTTPChecker already truncates, but
	// Checker is an exported interface and this is where the published 256-character guarantee
	// is actually spent: the reason goes to the node's logs and is stored as the archived job's
	// error for the queue's 30-day retention. Truncating an already-truncated reason is a
	// no-op, so the HTTP path is unaffected.
	reason = truncateReason(reason)

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
	cred *hmac.ClientConfig,
) (vtypes.Verifier, error) {
	if cfg == nil {
		return inner, nil
	}
	// Checked here rather than in Config.Validate because the credential lives in the secrets
	// file, and Config.Validate also runs where a job spec is built rather than run, on a
	// machine that has no business holding the verifier's secrets.
	if cfg.RequireAuth && cred == nil {
		return nil, errors.New(
			"policy_hook sets require_auth but no credential is configured; supply [policy_hook] api_key and secret_key in the verifier secrets file")
	}

	checker, err := NewHTTPChecker(lggr, cfg, cred)
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

	// The endpoint is logged as the full URL the verifier will POST, not as the configured base:
	// an operator debugging a 404 needs to see the path their server has to serve.
	//
	// authenticated is logged on every boot too: an operator whose endpoint checks signatures
	// needs to be able to see from the node's own logs that it is sending them.
	endpoint, err := cfg.EvaluateURL()
	if err != nil {
		return nil, err
	}
	lggr.Infow("Policy hook enabled",
		"endpoint", endpoint,
		"retryDelay", retryDelay,
		"authenticated", cred != nil,
	)

	return gated, nil
}
