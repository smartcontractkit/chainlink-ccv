package postgres

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const numSeedReports = 10_000

func BenchmarkSubmitAggregatedReport(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}
	storage, cleanup := setupTestDBForBench(b)
	defer cleanup()

	ctx := b.Context()
	signer1 := newTestSigner(b)
	signer2 := newTestSigner(b)

	reports := make([]*model.CommitAggregatedReport, 0, numSeedReports)
	for i := range numSeedReports {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i)
		msgWithCCV1 := createTestMessageWithCCV(b, message, signer1)
		messageID := getMessageIDFromProto(b, msgWithCCV1)
		aggKey := hex.EncodeToString(messageID)
		r1 := createTestCommitVerificationRecord(b, msgWithCCV1, signer1)
		r1.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, r1, aggKey); err != nil {
			b.Fatalf("save verification 1: %v", err)
		}
		msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
		r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
		r2.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, r2, aggKey); err != nil {
			b.Fatalf("save verification 2: %v", err)
		}
		reports = append(reports, &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggKey,
			Verifications:  []*model.CommitVerificationRecord{r1, r2},
		})
	}

	for b.Loop() {
		start := time.Now()
		for _, r := range reports {
			if err := storage.SubmitAggregatedReport(ctx, r); err != nil {
				b.Fatalf("submit aggregated report: %v", err)
			}
		}
		elapsed := time.Since(start)
		b.ReportMetric(float64(numSeedReports)/elapsed.Seconds(), "reports/sec")
		b.ReportMetric(float64(elapsed.Milliseconds()), "total-ms")
	}
}

func BenchmarkQueryAggregatedReports(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}
	storage, cleanup := setupTestDBForBench(b)
	defer cleanup()

	ctx := b.Context()
	signer1 := newTestSigner(b)
	signer2 := newTestSigner(b)

	for i := range numSeedReports {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i)
		msgWithCCV1 := createTestMessageWithCCV(b, message, signer1)
		messageID := getMessageIDFromProto(b, msgWithCCV1)
		aggKey := hex.EncodeToString(messageID)
		r1 := createTestCommitVerificationRecord(b, msgWithCCV1, signer1)
		r1.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, r1, aggKey); err != nil {
			b.Fatalf("save verification 1: %v", err)
		}
		msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
		r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
		r2.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, r2, aggKey); err != nil {
			b.Fatalf("save verification 2: %v", err)
		}
		report := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggKey,
			Verifications:  []*model.CommitVerificationRecord{r1, r2},
		}
		if err := storage.SubmitAggregatedReport(ctx, report); err != nil {
			b.Fatalf("submit aggregated report: %v", err)
		}
	}

	for b.Loop() {
		start := time.Now()
		var totalRead int
		var sinceSeq int64
		for {
			batch, err := storage.QueryAggregatedReports(ctx, sinceSeq)
			if err != nil {
				b.Fatalf("query aggregated reports: %v", err)
			}
			totalRead += len(batch.Reports)
			if !batch.HasMore {
				break
			}
			sinceSeq = batch.Reports[len(batch.Reports)-1].Sequence + 1
		}
		elapsed := time.Since(start)
		b.ReportMetric(float64(totalRead)/elapsed.Seconds(), "reports/sec")
		b.ReportMetric(float64(totalRead), "total-reports-read")
		b.ReportMetric(float64(elapsed.Milliseconds()), "total-ms")
	}
}

func BenchmarkQueryAggregatedReports_GrowingVolume(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	const volumeSteps = 10

	storage, cleanup := setupTestDBForBench(b)
	defer cleanup()

	ctx := b.Context()
	signer1 := newTestSigner(b)
	signer2 := newTestSigner(b)

	seqOffset := 0

	for step := 1; step <= volumeSteps; step++ {
		for i := range numSeedReports {
			message := createTestProtocolMessage()
			message.SequenceNumber = protocol.SequenceNumber(seqOffset + i)
			msgWithCCV1 := createTestMessageWithCCV(b, message, signer1)
			messageID := getMessageIDFromProto(b, msgWithCCV1)
			aggKey := hex.EncodeToString(messageID)
			r1 := createTestCommitVerificationRecord(b, msgWithCCV1, signer1)
			r1.MessageID = messageID
			if err := storage.SaveCommitVerification(ctx, r1, aggKey); err != nil {
				b.Fatalf("save verification 1: %v", err)
			}
			msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
			r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
			r2.MessageID = messageID
			if err := storage.SaveCommitVerification(ctx, r2, aggKey); err != nil {
				b.Fatalf("save verification 2: %v", err)
			}
			report := &model.CommitAggregatedReport{
				MessageID:      messageID,
				AggregationKey: aggKey,
				Verifications:  []*model.CommitVerificationRecord{r1, r2},
			}
			if err := storage.SubmitAggregatedReport(ctx, report); err != nil {
				b.Fatalf("submit aggregated report: %v", err)
			}
		}
		seqOffset += numSeedReports
		totalVolume := step * numSeedReports

		start := time.Now()
		var totalRead int
		var sinceSeq int64
		for totalRead < numSeedReports {
			batch, err := storage.QueryAggregatedReports(ctx, sinceSeq)
			if err != nil {
				b.Fatalf("query aggregated reports: %v", err)
			}
			totalRead += len(batch.Reports)
			if !batch.HasMore || len(batch.Reports) == 0 {
				break
			}
			sinceSeq = batch.Reports[len(batch.Reports)-1].Sequence + 1
		}
		elapsed := time.Since(start)

		b.Logf("volume=%d  read=%d  elapsed=%s  reports/sec=%.0f",
			totalVolume, totalRead, elapsed, float64(totalRead)/elapsed.Seconds())
	}
}

func setupTestDBForBench(b *testing.B) (*DatabaseStorage, func()) {
	b.Helper()
	storage, _, cleanup := setupTestDBWithDatabase(b)
	return storage, cleanup
}
