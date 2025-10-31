// Package common provides shared interfaces
package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// CommitVerificationStore defines an interface for storing and retrieving commit verification records.
type CommitVerificationStore interface {
	// SaveCommitVerification persists a commit verification record.
	SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error
	// GetCommitVerification retrieves a commit verification record by its identifier.
	GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error)
	// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID and committee ID.
	ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error)
	// ListOrphanedMessageIDs finds verification records that have not been aggregated yet.
	// Returns channels for streaming results: one for message/committee pairs, one for errors.
	ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error)
}

type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports retrieves all aggregated reports within a specific time range.
	QueryAggregatedReports(ctx context.Context, start int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error)
	// GetCCVData retrieves the aggregated CCV data for a specific message ID.
	GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error)
	// GetBatchCCVData retrieves the aggregated CCV data for multiple message IDs efficiently.
	// Returns a map of messageID hex string to CommitAggregatedReport. Missing message IDs are not included in the map.
	GetBatchCCVData(ctx context.Context, messageIDs []model.MessageID, committeeID string) (map[string]*model.CommitAggregatedReport, error)
}

// ChainStatus represents chain status data with finalized block height and disabled flag.
type ChainStatus struct {
	FinalizedBlockHeight uint64
	Disabled             bool
}

// ChainStatusStorageInterface defines the interface for chain status storage implementations.
type ChainStatusStorageInterface interface {
	// StoreChainStatus stores chain status data for a client.
	StoreChainStatus(ctx context.Context, clientID string, chainStatuses map[uint64]*ChainStatus) error
	// GetClientChainStatus retrieves all chain statuses for a specific client.
	GetClientChainStatus(ctx context.Context, clientID string) (map[uint64]*ChainStatus, error)
	// GetAllClients returns a list of all client IDs that have stored chain statuses.
	GetAllClients(ctx context.Context) ([]string, error)
}
