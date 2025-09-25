// Package storage provides storage implementations for the aggregator service.
package memory

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// reportWithSequence wraps a report with its sequence number for pagination
type reportWithSequence struct {
	Report *model.CommitAggregatedReport
	SeqNum int64
}

// InMemoryStorage is an in-memory implementation of the CommitVerificationStore interface.
type InMemoryStorage struct {
	records           *sync.Map
	aggregatedReports *sync.Map
	sequenceCounter   *int64
	mu                sync.Mutex
}

// SaveCommitVerification persists a commit verification record.
func (s *InMemoryStorage) SaveCommitVerification(_ context.Context, record *model.CommitVerificationRecord) error {
	id, err := record.GetID()
	if err != nil {
		return err
	}

	s.records.Store(id.ToIdentifier(), record)
	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (s *InMemoryStorage) GetCommitVerification(_ context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records.Load(id.ToIdentifier())
	if !exists {
		return nil, errors.New("record not found")
	}

	castRecord, ok := record.(*model.CommitVerificationRecord)
	if !ok {
		return nil, errors.New("type assertion failed")
	}

	return castRecord, nil
}

// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID.
func (s *InMemoryStorage) ListCommitVerificationByMessageID(_ context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	var results []*model.CommitVerificationRecord
	s.records.Range(func(key, value any) bool {
		if record, ok := value.(*model.CommitVerificationRecord); ok && bytes.Equal(record.MessageId, messageID) && record.CommitteeID == committee {
			results = append(results, record)
		}
		return true
	})
	return results, nil
}

func (s *InMemoryStorage) SubmitReport(_ context.Context, report *model.CommitAggregatedReport) error {
	id := report.GetID()
	report.Timestamp = time.Now().Unix()

	// Assign a unique sequence number for pagination
	s.mu.Lock()
	*s.sequenceCounter++
	seqNum := *s.sequenceCounter
	s.mu.Unlock()

	// Store the report with its sequence number as metadata
	reportWithSeqNum := &reportWithSequence{
		Report: report,
		SeqNum: seqNum,
	}

	s.aggregatedReports.Store(id, reportWithSeqNum)
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReports(_ context.Context, start, end int64, committeeID string, limit int, lastSeqNum *int64) (*model.PaginatedAggregatedReportsResponse, error) {
	// Collect all matching reports with their sequence numbers
	var allReportsWithSeq []*reportWithSequence
	s.aggregatedReports.Range(func(key, value any) bool {
		if reportWithSeq, ok := value.(*reportWithSequence); ok {
			report := reportWithSeq.Report
			if report.Timestamp >= start && report.Timestamp <= end && report.CommitteeID == committeeID {
				allReportsWithSeq = append(allReportsWithSeq, reportWithSeq)
			}
		}
		return true
	})

	// Sort by sequence number for consistent ordering
	sort.Slice(allReportsWithSeq, func(i, j int) bool {
		return allReportsWithSeq[i].SeqNum < allReportsWithSeq[j].SeqNum
	})

	// Apply cursor-based pagination using sequence numbers
	startIdx := 0
	if lastSeqNum != nil {
		// Find the first report with seqNum > lastSeqNum
		for i, reportWithSeq := range allReportsWithSeq {
			if reportWithSeq.SeqNum > *lastSeqNum {
				startIdx = i
				break
			}
		}
		if startIdx == 0 && len(allReportsWithSeq) > 0 && allReportsWithSeq[0].SeqNum <= *lastSeqNum {
			// All reports have seqNum <= lastSeqNum, so no more results
			return &model.PaginatedAggregatedReportsResponse{
				Reports:    []*model.CommitAggregatedReport{},
				HasMore:    false,
				LastSeqNum: nil,
			}, nil
		}
	}

	// Apply limit and determine if there are more pages
	endIdx := startIdx + limit
	hasMore := endIdx < len(allReportsWithSeq)
	if hasMore {
		endIdx = startIdx + limit
	} else {
		endIdx = len(allReportsWithSeq)
	}

	if startIdx >= len(allReportsWithSeq) {
		return &model.PaginatedAggregatedReportsResponse{
			Reports:    []*model.CommitAggregatedReport{},
			HasMore:    false,
			LastSeqNum: nil,
		}, nil
	}

	resultsWithSeq := allReportsWithSeq[startIdx:endIdx]
	results := make([]*model.CommitAggregatedReport, len(resultsWithSeq))
	for i, reportWithSeq := range resultsWithSeq {
		results[i] = reportWithSeq.Report
	}

	var resultLastSeqNum *int64
	if len(resultsWithSeq) > 0 {
		// Use the actual sequence number for pagination
		resultLastSeqNum = &resultsWithSeq[len(resultsWithSeq)-1].SeqNum
	}

	return &model.PaginatedAggregatedReportsResponse{
		Reports:    results,
		HasMore:    hasMore,
		LastSeqNum: resultLastSeqNum,
	}, nil
}

func (s *InMemoryStorage) GetCCVData(_ context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	id := model.GetAggregatedReportID(messageID, committeeID)
	if value, ok := s.aggregatedReports.Load(id); ok {
		if reportWithSeq, ok := value.(*reportWithSequence); ok && reportWithSeq.Report.CommitteeID == committeeID {
			return reportWithSeq.Report, nil
		}
	}
	return nil, nil
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	seqCounter := int64(0)
	return &InMemoryStorage{
		records:           new(sync.Map),
		aggregatedReports: new(sync.Map),
		sequenceCounter:   &seqCounter,
	}
}
