package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func makeValidWriteReq() *committeepb.WriteCommitteeVerifierNodeResultRequest {
	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	pbMsg, err := ccvcommon.MapProtocolMessageToProtoMessage(msg)
	if err != nil {
		panic(err)
	}

	executorAddr := makeTestExecutorAddress()
	ccvAddresses := [][]byte{make([]byte, 20)} // 20 bytes for EVM address
	hash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{ccvAddresses[0]},
		executorAddr,
	)
	if err != nil {
		panic(err)
	}
	pbMsg.CcvAndExecutorHash = hash[:]

	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
			Signature:       []byte{0x1},
			CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
			Message:         pbMsg,
			CcvAddresses:    ccvAddresses,
			ExecutorAddress: executorAddr,
		},
	}
}

func TestValidateWriteRequest_Success(t *testing.T) {
	req := makeValidWriteReq()
	require.NoError(t, validateWriteRequest(req))
}

func TestValidateWriteRequest_Errors(t *testing.T) {
	t.Run("nil_committee_verifier_node_result", func(t *testing.T) {
		req := &committeepb.WriteCommitteeVerifierNodeResultRequest{CommitteeVerifierNodeResult: nil}
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("missing_message", func(t *testing.T) {
		req := makeValidWriteReq()
		req.CommitteeVerifierNodeResult.Message = nil
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("missing_signature", func(t *testing.T) {
		req := makeValidWriteReq()
		req.CommitteeVerifierNodeResult.Signature = nil
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("empty_ccv_addresses", func(t *testing.T) {
		req := makeValidWriteReq()
		req.CommitteeVerifierNodeResult.CcvAddresses = [][]byte{}
		err := validateWriteRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ccv_addresses cannot be empty")
	})

	t.Run("source_equals_destination_chain_selector", func(t *testing.T) {
		msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(1), protocol.SequenceNumber(1), []byte{})
		pbMsg, err := ccvcommon.MapProtocolMessageToProtoMessage(msg)
		require.NoError(t, err)

		executorAddr := makeTestExecutorAddress()
		ccvAddresses := [][]byte{make([]byte, 20)} // 20 bytes for EVM address
		hash, err := protocol.ComputeCCVAndExecutorHash(
			[]protocol.UnknownAddress{ccvAddresses[0]},
			executorAddr,
		)
		require.NoError(t, err)
		pbMsg.CcvAndExecutorHash = hash[:]

		req := &committeepb.WriteCommitteeVerifierNodeResultRequest{
			CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
				Signature:       []byte{0x1},
				CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
				Message:         pbMsg,
				CcvAddresses:    ccvAddresses,
				ExecutorAddress: executorAddr,
			},
		}
		err = validateWriteRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "source_chain_selector and dest_chain_selector cannot be equal")
	})
}

func TestValidateReadRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		req := &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: make([]byte, 32), Address: []byte{0xAA}}
		require.NoError(t, validateReadRequest(req))
	})

	t.Run("bad_message_id_length", func(t *testing.T) {
		req := &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: []byte{0x1}, Address: []byte{0xAA}}
		require.Error(t, validateReadRequest(req))
	})

	t.Run("missing_address", func(t *testing.T) {
		req := &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: make([]byte, 32)}
		require.Error(t, validateReadRequest(req))
	})
}
