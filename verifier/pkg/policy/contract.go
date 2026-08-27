package policy

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// SchemaVersion identifies the request/response contract this verifier speaks. It is sent on
// every request so an endpoint serving several verifier releases can branch on it. The
// authoritative description of these types is verifier/policy_hook_openapi_v1.yaml; the two are
// kept in step by TestOpenAPISpecMatchesContract.
const SchemaVersion = "v1"

// Decision is the verdict an endpoint returns. Only PASS and FAIL are meaningful in v1; any
// other value is treated as an unusable response, which retries rather than drops.
type Decision string

const (
	// DecisionPass tells the verifier to sign and attest the message.
	DecisionPass Decision = "PASS"
	// DecisionFail tells the verifier to drop the message. It is not attested and not
	// auto-executed; recovery requires an operator to reschedule the archived job or to rewind
	// the checkpoint and replay.
	DecisionFail Decision = "FAIL"
)

// EvaluateRequest is the v1 request body. It carries the decoded message and its source-chain
// provenance so the endpoint does not have to fetch or decode anything itself.
type EvaluateRequest struct {
	// SchemaVersion is the contract version of this request, always "v1" for this release.
	SchemaVersion string `json:"schema_version"`
	// VerifierID identifies the committee verifier node making the call.
	VerifierID string `json:"verifier_id"`
	// MessageID is the CCIP message ID, 32 bytes hex-encoded with an 0x prefix.
	MessageID string `json:"message_id"`
	// SourceTxHash is the hash of the source-chain transaction that emitted the message.
	SourceTxHash string `json:"source_tx_hash"`
	// SourceBlockNumber is the source-chain block the message was emitted in.
	SourceBlockNumber uint64 `json:"source_block_number"`
	// FinalizedBlockNumber is the source chain's finalized head when the verifier read the
	// message.
	FinalizedBlockNumber uint64 `json:"finalized_block_number"`
	// BlockDepth is how far the message's block sits below that finalized head, zero when
	// the message's block is the finalized head or newer.
	BlockDepth uint64 `json:"block_depth"`
	// Message is the decoded CCIP message.
	Message MessageV1 `json:"message"`
}

// MessageV1 is the decoded CCIP message as published in the v1 contract. Byte fields are
// hex-encoded with an 0x prefix. It is a deliberate copy of the on-the-wire message rather than
// a re-export of protocol.Message: the published contract is frozen at v1 and must not shift
// when the internal message format gains fields.
type MessageV1 struct {
	// Version is the CCIP message format version.
	Version uint8 `json:"version"`
	// SourceChainSelector is the CCIP selector of the source chain.
	SourceChainSelector uint64 `json:"source_chain_selector"`
	// DestChainSelector is the CCIP selector of the destination chain.
	DestChainSelector uint64 `json:"dest_chain_selector"`
	// SequenceNumber is the per-lane sequence number of the message.
	SequenceNumber uint64 `json:"sequence_number"`
	// OnRampAddress is the source-chain onRamp that emitted the message.
	OnRampAddress string `json:"on_ramp_address"`
	// OffRampAddress is the destination-chain offRamp that will deliver the message.
	OffRampAddress string `json:"off_ramp_address"`
	// Sender is the source-chain account that sent the message.
	Sender string `json:"sender"`
	// Receiver is the destination-chain account that will receive the message.
	Receiver string `json:"receiver"`
	// Data is the message payload.
	Data string `json:"data"`
	// DestBlob is the destination-chain execution blob.
	DestBlob string `json:"dest_blob"`
	// ExecutionGasLimit is the gas limit reserved for execution on the destination chain.
	ExecutionGasLimit uint32 `json:"execution_gas_limit"`
	// CCIPReceiveGasLimit is the gas limit reserved for the receiver's ccipReceive call.
	CCIPReceiveGasLimit uint32 `json:"ccip_receive_gas_limit"`
	// Finality is the encoded finality requirement of the message.
	Finality uint32 `json:"finality"`
	// CCVAndExecutorHash commits to the CCVs and executor the message requested.
	CCVAndExecutorHash string `json:"ccv_and_executor_hash"`
	// TokenTransfer is the attached token transfer, absent for a message with no tokens.
	TokenTransfer *TokenTransferV1 `json:"token_transfer,omitempty"`
}

// TokenTransferV1 is the token transfer attached to a message, as published in the v1 contract.
type TokenTransferV1 struct {
	// Version is the token transfer format version.
	Version uint8 `json:"version"`
	// Amount is the transferred amount in the token's smallest unit, as a decimal string
	// because it does not fit a JSON number.
	Amount string `json:"amount"`
	// SourcePoolAddress is the source-chain token pool the tokens were locked or burned in.
	SourcePoolAddress string `json:"source_pool_address"`
	// SourceTokenAddress is the source-chain token contract.
	SourceTokenAddress string `json:"source_token_address"`
	// DestTokenAddress is the destination-chain token contract.
	DestTokenAddress string `json:"dest_token_address"`
	// TokenReceiver is the destination-chain account receiving the tokens.
	TokenReceiver string `json:"token_receiver"`
	// ExtraData is pool-specific data carried with the transfer.
	ExtraData string `json:"extra_data"`
}

// EvaluateResponse is the v1 response body, returned with HTTP 200.
type EvaluateResponse struct {
	// Decision is PASS or FAIL.
	Decision Decision `json:"decision"`
	// Reason optionally explains a FAIL. It is logged by the verifier and never signed.
	Reason string `json:"reason,omitempty"`
}

// NewEvaluateRequest builds the v1 request for a verification task.
func NewEvaluateRequest(verifierID string, task *vtypes.VerificationTask) EvaluateRequest {
	return EvaluateRequest{
		SchemaVersion:        SchemaVersion,
		VerifierID:           verifierID,
		MessageID:            task.MessageID,
		SourceTxHash:         hexBytes(task.TxHash),
		SourceBlockNumber:    task.BlockNumber,
		FinalizedBlockNumber: task.FinalizedBlockAtRead,
		BlockDepth:           blockDepth(task.BlockNumber, task.FinalizedBlockAtRead),
		Message:              newMessageV1(task.Message),
	}
}

// blockDepth reports how far below the finalized head the message's block sits. A message read
// off a safe (not finalized) head can sit above it, which reports zero rather than wrapping.
func blockDepth(blockNumber, finalizedBlock uint64) uint64 {
	if finalizedBlock <= blockNumber {
		return 0
	}
	return finalizedBlock - blockNumber
}

func newMessageV1(message protocol.Message) MessageV1 {
	out := MessageV1{
		Version:             message.Version,
		SourceChainSelector: uint64(message.SourceChainSelector),
		DestChainSelector:   uint64(message.DestChainSelector),
		SequenceNumber:      uint64(message.SequenceNumber),
		OnRampAddress:       hexAddress(message.OnRampAddress),
		OffRampAddress:      hexAddress(message.OffRampAddress),
		Sender:              hexAddress(message.Sender),
		Receiver:            hexAddress(message.Receiver),
		Data:                hexBytes(message.Data),
		DestBlob:            hexBytes(message.DestBlob),
		ExecutionGasLimit:   message.ExecutionGasLimit,
		CCIPReceiveGasLimit: message.CcipReceiveGasLimit,
		Finality:            uint32(message.Finality),
		CCVAndExecutorHash:  message.CcvAndExecutorHash.String(),
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

// parseDecision normalizes and validates an endpoint's verdict. Case is normalized because an
// endpoint answering "pass" plainly means PASS; anything that is not one of the two verdicts is
// an error, which retries.
func parseDecision(raw Decision) (Decision, error) {
	switch Decision(strings.ToUpper(strings.TrimSpace(string(raw)))) {
	case DecisionPass:
		return DecisionPass, nil
	case DecisionFail:
		return DecisionFail, nil
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
