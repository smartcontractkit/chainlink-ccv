package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func makeValidWriteReq() *pb.WriteCommitteeVerifierNodeResultRequest {
	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	return &pb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &pb.CommitteeVerifierNodeResult{
			Signature:       []byte{0x1},
			CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
			Message:         ccvcommon.MapProtocolMessageToProtoMessage(msg),
			CcvAddresses:    [][]byte{},
			ExecutorAddress: makeTestExecutorAddress(),
		},
	}
}

func TestValidateWriteRequest_Success(t *testing.T) {
	req := makeValidWriteReq()
	require.NoError(t, validateWriteRequest(req))
}

func TestValidateWriteRequest_Errors(t *testing.T) {
	t.Run("nil_committee_verifier_node_result", func(t *testing.T) {
		req := &pb.WriteCommitteeVerifierNodeResultRequest{CommitteeVerifierNodeResult: nil}
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
}

func TestValidateReadRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		req := &pb.ReadCommitteeVerifierNodeResultRequest{MessageId: make([]byte, 32)}
		require.NoError(t, validateReadRequest(req))
	})

	t.Run("bad_length", func(t *testing.T) {
		req := &pb.ReadCommitteeVerifierNodeResultRequest{MessageId: []byte{0x1}}
		require.Error(t, validateReadRequest(req))
	})
}
