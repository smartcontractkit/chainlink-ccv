package policy

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

func TestNewEvaluateRequest(t *testing.T) {
	task := vtypes.VerificationTask{
		MessageID:             "0xabc123",
		TxHash:                protocol.ByteSlice{0xde, 0xad, 0xbe, 0xef},
		BlockNumber:           100,
		FinalizedBlockAtReady: 115,
		Message: protocol.Message{
			Version:             1,
			SourceChainSelector: 3379446385462418246,
			DestChainSelector:   12922642891491394802,
			SequenceNumber:      7,
			OnRampAddress:       protocol.UnknownAddress{0x01, 0x02},
			OffRampAddress:      protocol.UnknownAddress{0x03, 0x04},
			Sender:              protocol.UnknownAddress{0x05},
			Receiver:            protocol.UnknownAddress{0x06},
			Data:                protocol.ByteSlice{0x07, 0x08},
			DestBlob:            protocol.ByteSlice{0x09},
			ExecutionGasLimit:   300000,
			CcipReceiveGasLimit: 200000,
			Finality:            protocol.FinalityWaitForFinality,
			CcvAndExecutorHash:  protocol.Bytes32{0x0a},
		},
	}

	req := NewEvaluateRequest("committee-verifier-1", &task)

	assert.Equal(t, SchemaVersion, req.SchemaVersion)
	assert.Equal(t, "committee-verifier-1", req.VerifierID)
	assert.Equal(t, "0xabc123", req.MessageID)
	assert.Equal(t, "0xdeadbeef", req.SourceTxHash)
	assert.Equal(t, uint64(100), req.SourceBlockNumber)
	assert.Equal(t, uint64(115), req.FinalizedBlockNumber)
	assert.Equal(t, uint64(15), req.BlockDepth)

	assert.Equal(t, uint8(1), req.Message.Version)
	assert.Equal(t, uint64(3379446385462418246), req.Message.SourceChainSelector)
	assert.Equal(t, uint64(12922642891491394802), req.Message.DestChainSelector)
	assert.Equal(t, uint64(7), req.Message.SequenceNumber)
	assert.Equal(t, "0x0102", req.Message.OnRampAddress)
	assert.Equal(t, "0x0304", req.Message.OffRampAddress)
	assert.Equal(t, "0x05", req.Message.Sender)
	assert.Equal(t, "0x06", req.Message.Receiver)
	assert.Equal(t, "0x0708", req.Message.Data)
	assert.Equal(t, "0x09", req.Message.DestBlob)
	assert.Equal(t, uint32(300000), req.Message.ExecutionGasLimit)
	assert.Equal(t, uint32(200000), req.Message.CCIPReceiveGasLimit)
	assert.Equal(t, uint32(0), req.Message.Finality)
	assert.Nil(t, req.Message.TokenTransfer, "a message with no tokens carries no token_transfer")
}

func TestNewEvaluateRequest_BlockDepth(t *testing.T) {
	tests := []struct {
		name      string
		block     uint64
		finalized uint64
		want      uint64
	}{
		{name: "message below the finalized head", block: 10, finalized: 25, want: 15},
		{name: "message at the finalized head", block: 25, finalized: 25, want: 0},
		// A message read off the safe head can sit above the finalized head. Reporting zero
		// keeps the field meaningful instead of wrapping around uint64.
		{name: "message above the finalized head", block: 30, finalized: 25, want: 0},
		{name: "no finalized head recorded", block: 30, finalized: 0, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := vtypes.VerificationTask{BlockNumber: tt.block, FinalizedBlockAtReady: tt.finalized}
			assert.Equal(t, tt.want, NewEvaluateRequest("v", &task).BlockDepth)
		})
	}
}

func TestNewEvaluateRequest_TokenTransfer(t *testing.T) {
	// An amount that overflows float64's exact integer range, to show why the contract sends it
	// as a decimal string.
	amount, ok := new(big.Int).SetString("123456789012345678901234567890", 10)
	require.True(t, ok)

	task := vtypes.VerificationTask{
		Message: protocol.Message{
			TokenTransfer: &protocol.TokenTransfer{
				Version:            2,
				Amount:             amount,
				SourcePoolAddress:  protocol.ByteSlice{0x11},
				SourceTokenAddress: protocol.ByteSlice{0x22},
				DestTokenAddress:   protocol.ByteSlice{0x33},
				TokenReceiver:      protocol.ByteSlice{0x44},
				ExtraData:          nil,
			},
		},
	}

	tt := NewEvaluateRequest("v", &task).Message.TokenTransfer
	require.NotNil(t, tt)
	assert.Equal(t, uint8(2), tt.Version)
	assert.Equal(t, "123456789012345678901234567890", tt.Amount)
	assert.Equal(t, "0x11", tt.SourcePoolAddress)
	assert.Equal(t, "0x22", tt.SourceTokenAddress)
	assert.Equal(t, "0x33", tt.DestTokenAddress)
	assert.Equal(t, "0x44", tt.TokenReceiver)
	assert.Equal(t, "0x", tt.ExtraData, "an absent byte field is 0x, not an empty string")

	// The amount survives a JSON round trip intact, which it would not as a number.
	encoded, err := json.Marshal(tt)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"amount":"123456789012345678901234567890"`)
}

func TestNewEvaluateRequest_NilAmount(t *testing.T) {
	task := vtypes.VerificationTask{
		Message: protocol.Message{TokenTransfer: &protocol.TokenTransfer{Version: 1}},
	}

	tt := NewEvaluateRequest("v", &task).Message.TokenTransfer
	require.NotNil(t, tt)
	assert.Equal(t, "0", tt.Amount)
}

func TestParseDecision(t *testing.T) {
	tests := []struct {
		name    string
		raw     Decision
		want    Decision
		wantErr bool
	}{
		{name: "PASS", raw: "PASS", want: DecisionPass},
		{name: "FAIL", raw: "FAIL", want: DecisionFail},
		// PASS is matched exactly and FAIL is not, on purpose. Misreading a verdict into a
		// retry costs a delay; misreading one into a signature attests a message the
		// endpoint may not have approved, so only the retry direction gets the benefit of
		// the doubt.
		{name: "lowercase pass", raw: "pass", wantErr: true},
		{name: "mixed case fail", raw: "Fail", want: DecisionFail},
		{name: "surrounding whitespace", raw: " PASS\n", want: DecisionPass},
		{name: "empty", raw: "", wantErr: true},
		{name: "unknown verdict", raw: "MAYBE", wantErr: true},
		// "ALLOW" is not PASS. An unrecognized verdict retries rather than being guessed at,
		// in either direction.
		{name: "near miss", raw: "ALLOW", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDecision(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTruncateReason(t *testing.T) {
	assert.Empty(t, truncateReason("   "))
	assert.Equal(t, "sanctioned sender", truncateReason("  sanctioned sender  "))

	long := strings.Repeat("x", maxReasonLength+50)
	got := truncateReason(long)
	assert.Len(t, got, maxReasonLength+len("...(truncated)"))
	assert.True(t, strings.HasSuffix(got, "...(truncated)"))
}
