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

const (
	addrSigner         = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrDestVerifier   = "0xcccccccccccccccccccccccccccccccccccccccc"
	addrSourceVerifier = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// buildCommittee is a helper to build a proper committee with quorum config.
// It also validates the config to populate parsed addresses.
func buildCommittee(destSel, srcSel uint64, destVerifierAddr string, signers []model.Signer) *model.Committee {
	config := &model.AggregatorConfig{
		Committee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				strconv.FormatUint(srcSel, 10): {
					Signers:               signers,
					Threshold:             1,
					SourceVerifierAddress: addrSourceVerifier,
				},
			},
			DestinationVerifiers: map[string]string{
				strconv.FormatUint(destSel, 10): destVerifierAddr,
			},
		},
	}
	// Validate to populate parsed addresses
	_ = config.ValidateCommitteeConfig()
	return config.Committee
}

// makeAggregatedReport creates a minimal aggregated report for testing purposes.
func makeAggregatedReport(msg *protocol.Message, msgID model.MessageID, sigAddr string) *model.CommitAggregatedReport {
	// ccv version must be at least 4 bytes to account for version
	ccvVersion := []byte{0x01, 0x02, 0x03, 0x04}
	// create one verification with source verifier address in ccvAddresses
	ccvAddresses := []protocol.UnknownAddress{
		protocol.UnknownAddress(common.HexToAddress(addrSourceVerifier).Bytes()),
	}
	executorAddress := protocol.UnknownAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}

	// Create a valid 64-byte signature (R:32 || S:32)
	signerAddr := common.HexToAddress(sigAddr)
	signature := make([]byte, protocol.SingleECDSASignatureSize)
	// R must be non-zero (32 bytes)
	for i := range 32 {
		signature[i] = byte(i + 1)
	}
	// S must be non-zero (32 bytes)
	for i := 32; i < 64; i++ {
		signature[i] = byte(i + 1)
	}

	// create one verification
	ver := &model.CommitVerificationRecord{
		MessageID: msgID,
		Message:   msg,
		SignerIdentifier: &model.SignerIdentifier{
			Identifier: signerAddr.Bytes(),
		},
		CCVVersion:             ccvVersion,
		Signature:              signature,
		MessageCCVAddresses:    ccvAddresses,
		MessageExecutorAddress: executorAddress,
	}
	ver.SetTimestampFromMillis(time.Now().UnixMilli())
	return &model.CommitAggregatedReport{
		MessageID:     msgID,
		Verifications: []*model.CommitVerificationRecord{ver},
		Sequence:      1,
		WrittenAt:     time.Now(),
	}
}

// assertAnError returns a non-nil error for mocks without importing fmt in test body.
func assertAnError() error {
	return status.Error(codes.Internal, "test error")
}

// makeTestMessage creates a valid protocol.Message for testing with proper CcvAndExecutorHash.
// This helper ensures all tests use valid messages that pass validation.
func makeTestMessage(sourceSel, destSel protocol.ChainSelector, seqNum protocol.SequenceNumber, data []byte) *protocol.Message {
	// Create valid executor address (20 bytes for EVM)
	executorAddr := make([]byte, 20)
	executorAddr[0] = 0xEE

	// Create CCV addresses (empty in this case for simple tests)
	var ccvAddresses []protocol.UnknownAddress

	// Compute valid CcvAndExecutorHash
	ccvAndExecutorHash, _ := protocol.ComputeCCVAndExecutorHash(ccvAddresses, protocol.UnknownAddress(executorAddr))

	msg, _ := protocol.NewMessage(sourceSel, destSel, seqNum, nil, nil, 0, 500_000, 500_000, ccvAndExecutorHash, nil, nil, data, []byte{}, nil)
	return msg
}

// makeTestExecutorAddress returns a valid 20-byte executor address for testing.
func makeTestExecutorAddress() []byte {
	executorAddr := make([]byte, 20)
	executorAddr[0] = 0xEE
	return executorAddr
}
