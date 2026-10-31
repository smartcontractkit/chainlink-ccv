package verifier

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerificationGuard rechecks safety state when queued tasks reach verification.
// Known unsafe tasks fail permanently; unavailable state fails retryably.
type VerificationGuard struct {
	inner              Verifier
	chainStatusManager protocol.ChainStatusManager
	curseDetector      common.CurseChecker
	messageRules       common.MessageRulesChecker
}

// NewVerificationGuard wraps inner with queued-task safety checks.
func NewVerificationGuard(
	inner Verifier,
	chainStatusManager protocol.ChainStatusManager,
	curseDetector common.CurseChecker,
	messageRules common.MessageRulesChecker,
) *VerificationGuard {
	return &VerificationGuard{
		inner:              inner,
		chainStatusManager: chainStatusManager,
		curseDetector:      curseDetector,
		messageRules:       messageRules,
	}
}

// VerifyMessages returns one result per task and forwards only tasks that pass every check.
func (g *VerificationGuard) VerifyMessages(ctx context.Context, tasks []VerificationTask) []VerificationResult {
	if len(tasks) == 0 {
		return nil
	}

	sources := make([]protocol.ChainSelector, 0, len(tasks))
	seenSources := make(map[protocol.ChainSelector]struct{}, len(tasks))
	for _, task := range tasks {
		source := task.Message.SourceChainSelector
		if _, seen := seenSources[source]; seen {
			continue
		}
		seenSources[source] = struct{}{}
		sources = append(sources, source)
	}

	readCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
	statuses, err := g.chainStatusManager.ReadChainStatuses(readCtx, sources)
	cancel()
	if err != nil {
		return verificationGuardErrorResults(tasks, fmt.Errorf("read source chain statuses: %w", err), true)
	}

	results := make([]VerificationResult, 0, len(tasks))
	allowed := make([]VerificationTask, 0, len(tasks))
	for _, task := range tasks {
		message := task.Message
		if status := statuses[message.SourceChainSelector]; status != nil && status.Disabled {
			results = append(results, verificationGuardErrorResult(
				task, fmt.Errorf("source chain %s is disabled", message.SourceChainSelector), false))
			continue
		}

		cursed, err := g.curseDetector.IsRemoteChainCursed(ctx, message.SourceChainSelector, message.DestChainSelector)
		if err != nil {
			results = append(results, verificationGuardErrorResult(task, fmt.Errorf("check curse state: %w", err), true))
			continue
		}
		if cursed {
			results = append(results, verificationGuardErrorResult(
				task, fmt.Errorf("lane from source chain %s to destination chain %s is cursed",
					message.SourceChainSelector, message.DestChainSelector), false))
			continue
		}

		disabled, err := g.messageRules.IsMessageDisabled(ctx, message)
		if err != nil {
			results = append(results, verificationGuardErrorResult(task, fmt.Errorf("check message rules: %w", err), true))
			continue
		}
		if disabled {
			results = append(results, verificationGuardErrorResult(
				task, fmt.Errorf("message %s is disabled by message rules", task.MessageID), false))
			continue
		}
		allowed = append(allowed, task)
	}

	if len(allowed) > 0 {
		results = append(results, g.inner.VerifyMessages(ctx, allowed)...)
	}
	return results
}

func verificationGuardErrorResults(tasks []VerificationTask, err error, retryable bool) []VerificationResult {
	results := make([]VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		results = append(results, verificationGuardErrorResult(task, err, retryable))
	}
	return results
}

func verificationGuardErrorResult(task VerificationTask, err error, retryable bool) VerificationResult {
	verificationErr := NewVerificationError(err, task)
	verificationErr.Retryable = retryable
	return VerificationResult{Error: &verificationErr}
}

var _ Verifier = (*VerificationGuard)(nil)
