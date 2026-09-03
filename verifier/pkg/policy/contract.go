package policy

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy/internal/policyapi"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// The request and response types are generated from the published contract
// (verifier/policy_hook_openapi_v1.yaml) into internal/policyapi and aliased here, so the wire
// types cannot drift from the spec an operator builds against: there is one definition and the
// spec is it. The names below are the package's own, kept stable across the switch to generation.
//
// Generation is why there is no longer a test asserting the Go types match the spec. That test
// existed because the two were maintained by hand; the failure it guarded against is now a
// compile error. TestPublishedMessageCoversProtocolMessage still earns its place: it is the only
// thing tying the published shape to protocol.Message, which is not generated from anything.
type (
	// EvaluateRequest is the v1 request body. It carries the decoded message and its
	// source-chain provenance so the endpoint does not have to fetch or decode anything itself.
	EvaluateRequest = policyapi.EvaluateRequest
	// EvaluateResponse is the v1 response body, returned with HTTP 200.
	EvaluateResponse = policyapi.EvaluateResponse
	// MessageV1 is the decoded CCIP message as published in the v1 contract. Byte fields are
	// hex-encoded with an 0x prefix. It is a deliberate copy of the on-the-wire message rather
	// than a re-export of protocol.Message: the published contract is frozen at v1 and must not
	// shift when the internal message format gains fields.
	MessageV1 = policyapi.Message
	// TokenTransferV1 is the token transfer attached to a message, as published in v1.
	TokenTransferV1 = policyapi.TokenTransfer
	// Decision is the verdict an endpoint returns. Only PASS and FAIL are implemented in v1;
	// any other value is treated as an unusable response, which retries rather than drops.
	Decision = policyapi.EvaluateResponseDecision
)

// SchemaVersion identifies the request/response contract this verifier speaks. It is sent on
// every request so an endpoint serving several verifier releases can branch on it.
const SchemaVersion = policyapi.V1

const (
	// DecisionPass tells the verifier to sign and attest the message.
	DecisionPass Decision = policyapi.PASS
	// DecisionFail tells the verifier to drop the message. It is not attested and not
	// auto-executed; recovery requires an operator to reschedule the archived job or to rewind
	// the checkpoint and replay.
	DecisionFail Decision = policyapi.FAIL
	// DecisionHold is reserved and not implemented. It names the third outcome screening
	// produces in practice, a match a human clears shortly afterwards, which v1 does not
	// express: an operator holds a message by answering FAIL and replaying it once the review
	// clears.
	//
	// The value is in the published enum so that adding the behavior later is additive rather
	// than a breaking change for an endpoint validating strictly against the spec. Until then
	// parseDecision refuses it, so an endpoint that ships HOLD early gets retries and a clear
	// error rather than a message silently signed or silently dropped. Nothing may read this
	// constant as a verdict; it exists to be rejected by name.
	DecisionHold Decision = policyapi.HOLD
)

// NewEvaluateRequest builds the v1 request for a verification task.
func NewEvaluateRequest(verifierID string, task *vtypes.VerificationTask) EvaluateRequest {
	return EvaluateRequest{
		SchemaVersion:        SchemaVersion,
		VerifierId:           verifierID,
		MessageId:            task.MessageID,
		SourceTxHash:         hexBytes(task.TxHash),
		SourceBlockNumber:    task.BlockNumber,
		FinalizedBlockNumber: task.FinalizedBlockAtReady,
		BlockDepth:           blockDepth(task.BlockNumber, task.FinalizedBlockAtReady),
		Message:              newMessageV1(task.Message),
	}
}

// blockDepth reports how far below the finalized head the message's block sits, measured against
// the head at the moment the message met its finality requirement. A message that satisfies its
// finality off the safe head can still sit above the finalized head, which reports zero rather
// than wrapping.
func blockDepth(blockNumber, finalizedBlock uint64) uint64 {
	if finalizedBlock <= blockNumber {
		return 0
	}
	return finalizedBlock - blockNumber
}

func newMessageV1(message protocol.Message) MessageV1 {
	out := MessageV1{
		Version:             message.Version,
		SourceChainSelector: message.SourceChainSelector.String(),
		DestChainSelector:   message.DestChainSelector.String(),
		SequenceNumber:      uint64(message.SequenceNumber),
		OnRampAddress:       hexAddress(message.OnRampAddress),
		OffRampAddress:      hexAddress(message.OffRampAddress),
		Sender:              hexAddress(message.Sender),
		Receiver:            hexAddress(message.Receiver),
		Data:                hexBytes(message.Data),
		DestBlob:            hexBytes(message.DestBlob),
		ExecutionGasLimit:   message.ExecutionGasLimit,
		CcipReceiveGasLimit: message.CcipReceiveGasLimit,
		Finality:            uint32(message.Finality),
		CcvAndExecutorHash:  message.CcvAndExecutorHash.String(),
	}
	if message.TokenTransfer != nil {
		tt := message.TokenTransfer
		out.TokenTransfer = &TokenTransferV1{
			Version:            tt.Version,
			Amount:             decimalAmount(tt.Amount),
			SourcePoolAddress:  hexBytes(tt.SourcePoolAddress),
			SourceTokenAddress: hexBytes(tt.SourceTokenAddress),
			DestTokenAddress:   hexBytes(tt.DestTokenAddress),
			TokenReceiver:      hexBytes(tt.TokenReceiver),
			ExtraData:          hexBytes(tt.ExtraData),
		}
	}
	return out
}

// hexBytes renders a byte slice as 0x-prefixed hex. An absent value renders as "0x" rather than
// an empty string so every byte field in the contract has the same shape.
func hexBytes(b protocol.ByteSlice) string {
	if len(b) == 0 {
		return "0x"
	}
	return b.String()
}

func hexAddress(a protocol.UnknownAddress) string {
	if len(a) == 0 {
		return "0x"
	}
	return a.String()
}

func decimalAmount(amount *big.Int) string {
	if amount == nil {
		return "0"
	}
	return amount.String()
}

// parseDecision validates an endpoint's verdict. PASS is matched exactly as the contract spells
// it, because it is the one answer that ends in a signature and an endpoint that does not match
// its own published contract is not one to guess on behalf of. FAIL is matched case-insensitively:
// misreading "fail" as unusable only sends the message back for a retry, so leniency there costs a
// delay rather than an unintended attestation. Anything else is an error, which retries.
func parseDecision(raw Decision) (Decision, error) {
	trimmed := strings.TrimSpace(string(raw))
	switch {
	case Decision(trimmed) == DecisionPass:
		return DecisionPass, nil
	case Decision(strings.ToUpper(trimmed)) == DecisionFail:
		return DecisionFail, nil
	case Decision(strings.ToUpper(trimmed)) == DecisionHold:
		// Named explicitly so an endpoint that ships the reserved value early gets told why it
		// is not honored, instead of the generic "unrecognized decision" that would send its
		// author looking for a typo.
		return "", fmt.Errorf("decision %q is reserved and not implemented in %s; hold a message by answering %q and replaying it once the review clears",
			DecisionHold, SchemaVersion, DecisionFail)
	default:
		return "", fmt.Errorf("unrecognized decision %q, expected %q or %q", raw, DecisionPass, DecisionFail)
	}
}

// truncateReason bounds an endpoint-supplied reason before it reaches the logs.
func truncateReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) <= maxReasonLength {
		return reason
	}
	return reason[:maxReasonLength] + "...(truncated)"
}
