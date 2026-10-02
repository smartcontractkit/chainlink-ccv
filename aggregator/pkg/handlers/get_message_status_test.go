package handlers

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	aggcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	statusSrcSel  = uint64(1)
	statusDestSel = uint64(2)
	signerA       = "0x00000000000000000000000000000000000000a1"
	signerB       = "0x00000000000000000000000000000000000000b2"
	signerC       = "0x00000000000000000000000000000000000000c3"
	outsider      = "0x00000000000000000000000000000000000000ff"
)

func statusCommittee(threshold uint8) *model.Committee {
	committee := buildCommittee(statusDestSel, statusSrcSel, addrDestVerifier,
		[]model.Signer{{Address: signerA}, {Address: signerB}, {Address: signerC}})
	committee.QuorumConfigs[strconv.FormatUint(statusSrcSel, 10)].Threshold = threshold
	return committee
}

func statusRecords(msg *protocol.Message, msgID model.MessageID, signers ...string) []*model.CommitVerificationRecord {
	records := make([]*model.CommitVerificationRecord, 0, len(signers))
	for _, signer := range signers {
		records = append(records, &model.CommitVerificationRecord{
			MessageID:        msgID,
			Message:          msg,
			SignerIdentifier: &model.SignerIdentifier{Identifier: common.HexToAddress(signer).Bytes()},
			CCVVersion:       []byte{0x01, 0x02, 0x03, 0x04},
			Signature:        validTestSignature(),
			MessageCCVAddresses: []protocol.UnknownAddress{
				protocol.UnknownAddress(common.HexToAddress(addrSourceVerifier).Bytes()),
			},
			MessageExecutorAddress: makeTestExecutorAddress(),
		})
	}
	return records
}

// validTestSignature returns a 64-byte R||S signature with non-zero halves.
func validTestSignature() []byte {
	signature := make([]byte, protocol.SingleECDSASignatureSize)
	for i := range signature {
		signature[i] = byte(i + 1)
	}
	return signature
}

func statusReport(key model.AggregationKey, records []*model.CommitVerificationRecord) map[string]*model.CommitAggregatedReport {
	return map[string]*model.CommitAggregatedReport{
		protocol.ByteSlice(records[0].MessageID).String(): {MessageID: records[0].MessageID, AggregationKey: key, Verifications: records},
	}
}

func withDiscoveryVersion(records []*model.CommitVerificationRecord) []*model.CommitVerificationRecord {
	for _, record := range records {
		record.CCVVersion = protocol.MessageDiscoveryVersion
	}
	return records
}

func withoutCCVAddresses(records []*model.CommitVerificationRecord) []*model.CommitVerificationRecord {
	for _, record := range records {
		record.MessageCCVAddresses = nil
	}
	return records
}

func TestGetMessageStatusHandler(t *testing.T) {
	msg := makeTestMessage(protocol.ChainSelector(statusSrcSel), protocol.ChainSelector(statusDestSel), 1, nil)
	msgID, err := msg.MessageID()
	require.NoError(t, err)
	unknownSrcMsg := makeTestMessage(99, protocol.ChainSelector(statusDestSel), 1, nil)

	tests := []struct {
		name           string
		messageID      []byte
		records        map[model.AggregationKey][]*model.CommitVerificationRecord
		listErr        error
		reports        map[string]*model.CommitAggregatedReport
		reportErr      error
		wantCode       codes.Code
		wantCount      uint32
		wantThreshold  uint32
		wantAggregated bool
	}{
		{
			name:      "invalid message ID length",
			messageID: []byte{0x01},
			wantCode:  codes.InvalidArgument,
		},
		{
			name:     "no records",
			records:  map[model.AggregationKey][]*model.CommitVerificationRecord{},
			wantCode: codes.NotFound,
		},
		{
			name:     "list error",
			listErr:  assertAnError(),
			wantCode: codes.Internal,
		},
		{
			name:     "too many records",
			listErr:  fmt.Errorf("wrapped: %w", aggcommon.ErrTooManyRecords),
			wantCode: codes.FailedPrecondition,
		},
		{
			name:      "report error",
			records:   map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": statusRecords(msg, msgID[:], signerA)},
			reportErr: assertAnError(),
			wantCode:  codes.Internal,
		},
		{
			name:     "unknown quorum config",
			records:  map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": statusRecords(unknownSrcMsg, msgID[:], signerA)},
			wantCode: codes.NotFound,
		},
		{
			name:          "CCV addresses without the source verifier still show progress",
			records:       map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": withoutCCVAddresses(statusRecords(msg, msgID[:], signerA, signerB))},
			wantCount:     2,
			wantThreshold: 2,
		},
		{
			name:          "partial quorum ignores signers outside the committee",
			records:       map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": statusRecords(msg, msgID[:], signerA, outsider)},
			wantCount:     1,
			wantThreshold: 2,
		},
		{
			name:           "aggregated with verifications above the threshold",
			records:        map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": statusRecords(msg, msgID[:], signerA, signerB, signerC)},
			reports:        statusReport("k1", statusRecords(msg, msgID[:], signerA, signerB)),
			wantCount:      3,
			wantThreshold:  2,
			wantAggregated: true,
		},
		{
			name: "multiple keys without report uses the key with most signers",
			records: map[model.AggregationKey][]*model.CommitVerificationRecord{
				"k1": statusRecords(msg, msgID[:], signerA),
				"k2": statusRecords(msg, msgID[:], signerB, signerC),
			},
			wantCount:     2,
			wantThreshold: 3,
		},
		{
			name: "multiple keys with report uses the key of the report",
			records: map[model.AggregationKey][]*model.CommitVerificationRecord{
				"k1": statusRecords(msg, msgID[:], signerA),
				"k2": statusRecords(msg, msgID[:], signerB, signerC),
			},
			reports:        statusReport("k1", statusRecords(msg, msgID[:], signerA)),
			wantCount:      1,
			wantThreshold:  1,
			wantAggregated: true,
		},
		{
			name:           "message-discovery report is aggregated without the result API checks",
			records:        map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": withDiscoveryVersion(withoutCCVAddresses(statusRecords(msg, msgID[:], signerA, signerB)))},
			reports:        statusReport("k1", withDiscoveryVersion(withoutCCVAddresses(statusRecords(msg, msgID[:], signerA, signerB)))),
			wantCount:      2,
			wantThreshold:  2,
			wantAggregated: true,
		},
		{
			name:          "stored report below the current threshold is not aggregated",
			records:       map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": statusRecords(msg, msgID[:], signerA, signerB)},
			reports:       statusReport("k1", statusRecords(msg, msgID[:], signerA, signerB)),
			wantCount:     2,
			wantThreshold: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := mocks.NewMockMessageStatusReader(t)
			messageID := tc.messageID
			if messageID == nil {
				messageID = msgID[:]
				store.EXPECT().ListCommitVerificationByMessageID(mock.Anything, mock.Anything).Return(tc.records, tc.listErr)
				if tc.listErr == nil && len(tc.records) > 0 {
					store.EXPECT().GetBatchAggregatedReportByMessageIDs(mock.Anything, mock.Anything).Return(tc.reports, tc.reportErr)
				}
			}
			threshold := uint8(2)
			if tc.wantThreshold != 0 {
				threshold = uint8(tc.wantThreshold)
			}
			handler := NewGetMessageStatusHandler(store, statusCommittee(threshold), logger.TestSugared(t))

			resp, err := handler.Handle(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: messageID})
			if tc.wantCode != codes.OK {
				require.Equal(t, tc.wantCode, status.Code(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, messageID, resp.GetMessageId())
			require.Equal(t, tc.wantCount, resp.GetVerificationCount())
			require.Equal(t, tc.wantThreshold, resp.GetThreshold())
			require.Equal(t, tc.wantAggregated, resp.GetAggregated())
		})
	}
}

func TestGetMessageStatusHandler_Timestamps(t *testing.T) {
	msg := makeTestMessage(protocol.ChainSelector(statusSrcSel), protocol.ChainSelector(statusDestSel), 1, nil)
	msgID, err := msg.MessageID()
	require.NoError(t, err)
	writtenAt := time.UnixMilli(5_000)

	// Signers verify at 1000, 2000 and 3000 ms. The outsider at 4000 ms must not count.
	timedRecords := func(signers ...string) []*model.CommitVerificationRecord {
		records := statusRecords(msg, msgID[:], signers...)
		for i, record := range records {
			record.SetTimestampFromMillis(int64(i+1) * 1000)
		}
		return records
	}
	reportAt := func(records []*model.CommitVerificationRecord) map[string]*model.CommitAggregatedReport {
		reports := statusReport("k1", records)
		for _, report := range reports {
			report.WrittenAt = writtenAt
		}
		return reports
	}

	tests := []struct {
		name             string
		threshold        uint8
		records          []*model.CommitVerificationRecord
		reports          map[string]*model.CommitAggregatedReport
		wantFirst        int64
		wantLatest       int64
		wantAggregatedAt int64
	}{
		{
			name:       "not aggregated has no aggregated_at",
			threshold:  3,
			records:    timedRecords(signerA, signerB),
			wantFirst:  1000,
			wantLatest: 2000,
		},
		{
			name:             "aggregated sets aggregated_at and ignores signers outside the committee",
			threshold:        2,
			records:          timedRecords(signerA, signerB, signerC, outsider),
			reports:          reportAt(timedRecords(signerA, signerB)),
			wantFirst:        1000,
			wantLatest:       3000,
			wantAggregatedAt: writtenAt.UnixMilli(),
		},
		{
			name:       "stored report below the current threshold has no aggregated_at",
			threshold:  3,
			records:    timedRecords(signerA, signerB),
			reports:    reportAt(timedRecords(signerA, signerB)),
			wantFirst:  1000,
			wantLatest: 2000,
		},
		{
			name:      "no committee signers has zero times",
			threshold: 2,
			records:   timedRecords(outsider),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := mocks.NewMockMessageStatusReader(t)
			store.EXPECT().ListCommitVerificationByMessageID(mock.Anything, mock.Anything).
				Return(map[model.AggregationKey][]*model.CommitVerificationRecord{"k1": tc.records}, nil)
			store.EXPECT().GetBatchAggregatedReportByMessageIDs(mock.Anything, mock.Anything).Return(tc.reports, nil)
			handler := NewGetMessageStatusHandler(store, statusCommittee(tc.threshold), logger.TestSugared(t))

			resp, err := handler.Handle(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: msgID[:]})
			require.NoError(t, err)
			require.Equal(t, tc.wantFirst, resp.GetFirstVerificationAt(), "first_verification_at")
			require.Equal(t, tc.wantLatest, resp.GetLatestVerificationAt(), "latest_verification_at")
			require.Equal(t, tc.wantAggregatedAt, resp.GetAggregatedAt(), "aggregated_at")
		})
	}
}
