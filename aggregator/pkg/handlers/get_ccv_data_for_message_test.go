package handlers

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// helper to build a proper committee with quorum config.
func buildCommittee(destSel uint64, destVerifierAddr string, signers []model.Signer) *model.Committee {
	return &model.Committee{
		QuorumConfigs: map[string]*model.QuorumConfig{
			strconv.FormatUint(destSel, 10): {
				CommitteeVerifierAddress: destVerifierAddr,
				Signers:                  signers,
				Threshold:                1,
			},
		},
	}
}

func makeAggregatedReport(msgID model.MessageID, srcSel, dstSel uint64, srcAddr, sigAddr string) *model.CommitAggregatedReport {
	// minimal protocol message
	msg, _ := protocol.NewMessage(protocol.ChainSelector(srcSel), protocol.ChainSelector(dstSel), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	// blob data must be at least 4 bytes to account for version
	blobData := []byte{0x01, 0x02, 0x03, 0x04}
	// create one verification
	ver := &model.CommitVerificationRecord{
		MessageID:             msgID,
		SourceVerifierAddress: common.HexToAddress(srcAddr).Bytes(),
		Message:               msg,
		Timestamp:             time.Now(),
		IdentifierSigner: &model.IdentifierSigner{
			Address: common.HexToAddress(sigAddr).Bytes(),
		},
		BlobData: blobData,
		ReceiptBlobs: []*model.ReceiptBlob{
			{
				Issuer: common.HexToAddress(srcAddr).Bytes(),
				Blob:   blobData,
			},
		},
	}
	return &model.CommitAggregatedReport{
		MessageID:     msgID,
		Verifications: []*model.CommitVerificationRecord{ver},
		Sequence:      1,
		WrittenAt:     time.Now(),
		WinningReceiptBlobs: []*model.ReceiptBlob{
			{
				Issuer: common.HexToAddress(srcAddr).Bytes(),
				Blob:   blobData,
			},
		},
	}
}

func TestGetCCVDataForMessageHandler_Handle_Cases(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)

	const (
		sourceSel = uint64(1)
		destSel   = uint64(2)
	)
	msg, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	msgID, _ := msg.MessageID()

	signerAddr := addrSigner
	sourceVerifierAddr := addrSourceVerifier
	destVerifierAddr := addrDestVerifier

	committee := buildCommittee(destSel, destVerifierAddr, []model.Signer{{Address: signerAddr}})

	goodReport := makeAggregatedReport(msgID[:], sourceSel, destSel, sourceVerifierAddr, signerAddr)

	t.Run("success_returns_verifier_result", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		h := NewGetCCVDataForMessageHandler(store, committee, lggr)
		store.EXPECT().GetCCVData(mock.Anything, mock.Anything).Return(goodReport, nil)
		resp, err := h.Handle(context.Background(), &pb.GetVerifierResultForMessageRequest{MessageId: msgID[:]})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Message)
		require.Equal(t, int64(1), resp.Sequence)
		// encoded signatures present
		require.NotEmpty(t, resp.CcvData)
	})

	t.Run("storage_error_returns_internal", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		h := NewGetCCVDataForMessageHandler(store, committee, lggr)
		store.EXPECT().GetCCVData(mock.Anything, mock.Anything).Return(nil, assertAnError())
		resp, err := h.Handle(context.Background(), &pb.GetVerifierResultForMessageRequest{MessageId: msgID[:]})
		require.Error(t, err)
		require.Nil(t, resp)
		require.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("not_found_returns_not_found", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		h := NewGetCCVDataForMessageHandler(store, committee, lggr)
		store.EXPECT().GetCCVData(mock.Anything, mock.Anything).Return(nil, nil)
		resp, err := h.Handle(context.Background(), &pb.GetVerifierResultForMessageRequest{MessageId: msgID[:]})
		require.Error(t, err)
		require.Nil(t, resp)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("mapping_error_returns_internal", func(t *testing.T) {
		badReport := makeAggregatedReport(msgID[:], sourceSel, 99999, sourceVerifierAddr, signerAddr)
		store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		store.EXPECT().GetCCVData(mock.Anything, mock.Anything).Return(badReport, nil)
		h := NewGetCCVDataForMessageHandler(store, committee, lggr)
		resp, err := h.Handle(context.Background(), &pb.GetVerifierResultForMessageRequest{MessageId: msgID[:]})
		require.Error(t, err)
		require.Nil(t, resp)
		require.Equal(t, codes.Internal, status.Code(err))
	})
}

// assertAnError returns a non-nil error for mocks without importing fmt in test body above.
func assertAnError() error { return status.Error(codes.Internal, "boom") }
