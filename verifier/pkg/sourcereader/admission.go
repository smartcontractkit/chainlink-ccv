package sourcereader

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

type admissionDecision int

const (
	admissionWait admissionDecision = iota
	admissionReady
	admissionDrop
)

// admission is the single admission path for live polling and range recovery.
// Unknown rule/curse state is a wait, never evidence of a permanent drop.
func (r *Service) admission(ctx context.Context, task verifier.VerificationTask, latest, safe, finalized *big.Int) (admissionDecision, string, error) {
	cursed, err := r.curseDetector.IsRemoteChainCursed(ctx, task.Message.SourceChainSelector, task.Message.DestChainSelector)
	if err != nil {
		return admissionWait, monitoring.MessageTransitionReasonCurseStateUnknown, err
	}
	if cursed {
		return admissionDrop, monitoring.MessageTransitionReasonRemoteChainCursed, nil
	}
	disabled, err := r.messageRules.IsMessageDisabled(ctx, task.Message)
	if err != nil {
		return admissionWait, monitoring.MessageTransitionReasonRulesStateUnknown, err
	}
	if disabled {
		return admissionDrop, monitoring.MessageTransitionReasonMessageDisablementRule, nil
	}
	if !r.isMessageReadyForVerification(task, latest, safe, finalized) {
		return admissionWait, "pending_finality", nil
	}
	return admissionReady, "", nil
}
