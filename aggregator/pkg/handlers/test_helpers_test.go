package handlers

import (
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// buildCommittee is a helper to build a proper committee with quorum config.
func buildCommittee(destSel, srcSel uint64, destVerifierAddr string, signers []model.Signer) *model.Committee {
	return &model.Committee{
		QuorumConfigs: map[string]map[string]*model.QuorumConfig{
			strconv.FormatUint(destSel, 10): {
				strconv.FormatUint(srcSel, 10): {
					CommitteeVerifierAddress: destVerifierAddr,
					Signers:                  signers,
					Threshold:                1,
				},
			},
		},
	}
}

// makeAggregatedReport creates a minimal aggregated report for testing purposes.
func makeAggregatedReport(msg *protocol.Message, msgID model.MessageID, srcAddr, sigAddr string) *model.CommitAggregatedReport {
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

// assertAnError returns a non-nil error for mocks without importing fmt in test body.
func assertAnError() error {
	return status.Error(codes.Internal, "test error")
}
