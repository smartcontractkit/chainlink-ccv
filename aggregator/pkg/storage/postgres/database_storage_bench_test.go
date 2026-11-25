package postgres

import (
	"encoding/hex"
	"sync"
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
	reports := seedAggregatedReports(b, storage, numSeedReports, 0)

	for b.Loop() {
		start := time.Now()
		for _, r := range reports {
			if _, err := storage.SubmitAggregatedReport(ctx, r); err != nil {
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
		if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r1, AggregationKey: aggKey}}); err != nil {
			b.Fatalf("save verification 1: %v", err)
		}
		msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
		r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
		r2.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r2, AggregationKey: aggKey}}); err != nil {
			b.Fatalf("save verification 2: %v", err)
		}
		report := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggKey,
			Verifications:  []*model.CommitVerificationRecord{r1, r2},
		}
		if _, err := storage.SubmitAggregatedReport(ctx, report); err != nil {
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
			if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r1, AggregationKey: aggKey}}); err != nil {
				b.Fatalf("save verification 1: %v", err)
			}
			msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
			r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
			r2.MessageID = messageID
			if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r2, AggregationKey: aggKey}}); err != nil {
				b.Fatalf("save verification 2: %v", err)
			}
			report := &model.CommitAggregatedReport{
				MessageID:      messageID,
				AggregationKey: aggKey,
				Verifications:  []*model.CommitVerificationRecord{r1, r2},
			}
			if _, err := storage.SubmitAggregatedReport(ctx, report); err != nil {
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

// seedAggregatedReports saves two verifications per message and returns the reports, not yet submitted.
func seedAggregatedReports(b *testing.B, storage *DatabaseStorage, n, firstSeq int) []*model.CommitAggregatedReport {
	b.Helper()
	ctx := b.Context()
	signer1 := newTestSigner(b)
	signer2 := newTestSigner(b)

	reports := make([]*model.CommitAggregatedReport, 0, n)
	for i := range n {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(firstSeq + i)
		msgWithCCV1 := createTestMessageWithCCV(b, message, signer1)
		messageID := getMessageIDFromProto(b, msgWithCCV1)
		aggKey := hex.EncodeToString(messageID)
		r1 := createTestCommitVerificationRecord(b, msgWithCCV1, signer1)
		r1.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r1, AggregationKey: aggKey}}); err != nil {
			b.Fatalf("save verification 1: %v", err)
		}
		msgWithCCV2 := createTestMessageWithCCV(b, message, signer2)
		r2 := createTestCommitVerificationRecord(b, msgWithCCV2, signer2)
		r2.MessageID = messageID
		if err := storage.SaveCommitVerification(ctx, []model.CommitVerificationWrite{{Record: r2, AggregationKey: aggKey}}); err != nil {
			b.Fatalf("save verification 2: %v", err)
		}
		reports = append(reports, &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggKey,
			Verifications:  []*model.CommitVerificationRecord{r1, r2},
		})
	}
	return reports
}

// submitConcurrently submits all reports with a fixed number of workers and reports the throughput.
func submitConcurrently(b *testing.B, storage *DatabaseStorage, reports []*model.CommitAggregatedReport, workers int) {
	b.Helper()
	ctx := b.Context()
	work := make(chan *model.CommitAggregatedReport)
	var wg sync.WaitGroup
	start := time.Now()
	for range workers {
		wg.Go(func() {
			for r := range work {
				if _, err := storage.SubmitAggregatedReport(ctx, r); err != nil {
					b.Errorf("submit aggregated report: %v", err)
				}
			}
		})
	}
	for _, r := range reports {
		work <- r
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start)
	b.ReportMetric(float64(len(reports))/elapsed.Seconds(), "reports/sec")
}

func BenchmarkSubmitAggregatedReport_Concurrent(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}
	const (
		workers   = 4
		batchSize = 2_000
	)

	b.Run("new", func(b *testing.B) {
		storage, cleanup := setupTestDBForBench(b)
		defer cleanup()
		firstSeq := 0
		for b.Loop() {
			b.StopTimer()
			reports := seedAggregatedReports(b, storage, batchSize, firstSeq)
			firstSeq += batchSize
			b.StartTimer()
			submitConcurrently(b, storage, reports, workers)
		}
	})

	b.Run("duplicate", func(b *testing.B) {
		storage, cleanup := setupTestDBForBench(b)
		defer cleanup()
		reports := seedAggregatedReports(b, storage, batchSize, 0)
		submitConcurrently(b, storage, reports, workers)
		for b.Loop() {
			submitConcurrently(b, storage, reports, workers)
		}
	})
}
