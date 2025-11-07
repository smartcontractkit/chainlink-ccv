package handlers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func makeValidWriteReq(idempotencyKey string) *pb.WriteCommitCCVNodeDataRequest {
	msg, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	id, _ := msg.MessageID()
	return &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: &pb.MessageWithCCVNodeData{
			MessageId: id[:],
			CcvData:   []byte{0x1},
			Timestamp: time.Now().UnixMilli(),
			Message:   model.MapProtocolMessageToProtoMessage(msg),
		},
		IdempotencyKey: idempotencyKey,
	}
}

func TestValidateWriteRequest_Success(t *testing.T) {
	req := makeValidWriteReq("550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, validateWriteRequest(req))
}

func TestValidateWriteRequest_Errors(t *testing.T) {
	t.Run("nil_ccv_node_data", func(t *testing.T) {
		req := &pb.WriteCommitCCVNodeDataRequest{CcvNodeData: nil, IdempotencyKey: "550e8400-e29b-41d4-a716-446655440000"}
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("bad_uuid", func(t *testing.T) {
		req := makeValidWriteReq("not-a-uuid")
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("message_id_mismatch", func(t *testing.T) {
		req := makeValidWriteReq("550e8400-e29b-41d4-a716-446655440000")
		req.CcvNodeData.MessageId[0] ^= 0xFF
		require.Error(t, validateWriteRequest(req))
	})

	t.Run("timestamp_out_of_range", func(t *testing.T) {
		req := makeValidWriteReq("550e8400-e29b-41d4-a716-446655440000")
		req.CcvNodeData.Timestamp = time.Now().Add(200 * 365 * 24 * time.Hour).UnixMilli()
		require.Error(t, validateWriteRequest(req))
	})
}

func TestValidateReadRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		req := &pb.ReadCommitCCVNodeDataRequest{MessageId: make([]byte, 32)}
		require.NoError(t, validateReadRequest(req))
	})

	t.Run("bad_length", func(t *testing.T) {
		req := &pb.ReadCommitCCVNodeDataRequest{MessageId: []byte{0x1}}
		require.Error(t, validateReadRequest(req))
	})
}

func TestIsValidMillisecondTimestamp_Bounds(t *testing.T) {
	now := time.Now()
	tooPast := now.Add(-101 * 365 * 24 * time.Hour).UnixMilli()
	tooFuture := now.Add(101 * 365 * 24 * time.Hour).UnixMilli()
	inside := now.UnixMilli()

	require.False(t, isValidMillisecondTimestamp(tooPast))
	require.False(t, isValidMillisecondTimestamp(tooFuture))
	require.True(t, isValidMillisecondTimestamp(inside))
}
