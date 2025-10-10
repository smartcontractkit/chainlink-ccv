package ddb

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

// CheckpointRecord represents a checkpoint entry in DynamoDB.
type CheckpointRecord struct {
	ClientID             string `json:"client_id"`
	ChainSelector        uint64 `json:"chain_selector"`
	FinalizedBlockHeight uint64 `json:"finalized_block_height"`
	LastUpdated          int64  `json:"last_updated"`
}

// CheckpointDTO handles marshaling and unmarshaling of checkpoint records to/from DynamoDB items.
type CheckpointDTO struct{}

// ToItem converts a CheckpointRecord to a DynamoDB item.
func (dto *CheckpointDTO) ToItem(record *CheckpointRecord) (map[string]types.AttributeValue, error) {
	if record == nil {
		return nil, fmt.Errorf("checkpoint record cannot be nil")
	}

	if record.ClientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}

	if record.ChainSelector == 0 {
		return nil, fmt.Errorf("chain selector must be greater than 0")
	}

	if record.FinalizedBlockHeight == 0 {
		return nil, fmt.Errorf("finalized block height must be greater than 0")
	}

	// Set LastUpdated to current time if not set
	if record.LastUpdated == 0 {
		record.LastUpdated = time.Now().Unix()
	}

	item := map[string]types.AttributeValue{
		ddbconstant.CheckpointFieldClientID: &types.AttributeValueMemberS{
			Value: record.ClientID,
		},
		ddbconstant.CheckpointFieldChainSelector: &types.AttributeValueMemberN{
			Value: strconv.FormatUint(record.ChainSelector, 10),
		},
		ddbconstant.CheckpointFieldFinalizedBlockHeight: &types.AttributeValueMemberN{
			Value: strconv.FormatUint(record.FinalizedBlockHeight, 10),
		},
		ddbconstant.CheckpointFieldLastUpdated: &types.AttributeValueMemberN{
			Value: strconv.FormatInt(record.LastUpdated, 10),
		},
	}

	return item, nil
}

// FromItem converts a DynamoDB item to a CheckpointRecord.
func (dto *CheckpointDTO) FromItem(item map[string]types.AttributeValue) (*CheckpointRecord, error) {
	if item == nil {
		return nil, fmt.Errorf("item cannot be nil")
	}

	// Extract ClientID
	clientIDAttr, ok := item[ddbconstant.CheckpointFieldClientID].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.CheckpointFieldClientID)
	}

	// Extract ChainSelector
	chainSelectorAttr, ok := item[ddbconstant.CheckpointFieldChainSelector].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.CheckpointFieldChainSelector)
	}
	chainSelector, err := strconv.ParseUint(chainSelectorAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse chain selector: %w", err)
	}

	// Extract FinalizedBlockHeight
	blockHeightAttr, ok := item[ddbconstant.CheckpointFieldFinalizedBlockHeight].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.CheckpointFieldFinalizedBlockHeight)
	}
	blockHeight, err := strconv.ParseUint(blockHeightAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse finalized block height: %w", err)
	}

	// Extract LastUpdated
	lastUpdatedAttr, ok := item[ddbconstant.CheckpointFieldLastUpdated].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.CheckpointFieldLastUpdated)
	}
	lastUpdated, err := strconv.ParseInt(lastUpdatedAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last updated: %w", err)
	}

	return &CheckpointRecord{
		ClientID:             clientIDAttr.Value,
		ChainSelector:        chainSelector,
		FinalizedBlockHeight: blockHeight,
		LastUpdated:          lastUpdated,
	}, nil
}

// ToCheckpointMap converts a slice of CheckpointRecord to the format expected by CheckpointStorageInterface.
func (dto *CheckpointDTO) ToCheckpointMap(records []*CheckpointRecord) map[uint64]uint64 {
	result := make(map[uint64]uint64, len(records))
	for _, record := range records {
		result[record.ChainSelector] = record.FinalizedBlockHeight
	}
	return result
}

// FromCheckpointMap converts the CheckpointStorageInterface format to CheckpointRecord slice.
func (dto *CheckpointDTO) FromCheckpointMap(clientID string, checkpoints map[uint64]uint64) []*CheckpointRecord {
	result := make([]*CheckpointRecord, 0, len(checkpoints))
	now := time.Now().Unix()

	for chainSelector, blockHeight := range checkpoints {
		result = append(result, &CheckpointRecord{
			ClientID:             clientID,
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
			LastUpdated:          now,
		})
	}

	return result
}
