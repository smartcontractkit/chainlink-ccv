package ddb

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

// ChainStatusRecord represents a chain status entry in DynamoDB.
type ChainStatusRecord struct {
	ClientID             string
	ChainSelector        uint64
	FinalizedBlockHeight uint64
	Disabled             bool
	LastUpdated          time.Time
}

// ChainStatusDTO handles marshaling and unmarshaling of chain status records to/from DynamoDB items.
type ChainStatusDTO struct{}

// ToItem converts a ChainStatusRecord to a DynamoDB item.
func (dto *ChainStatusDTO) ToItem(record *ChainStatusRecord) (map[string]types.AttributeValue, error) {
	if record == nil {
		return nil, fmt.Errorf("chain status record cannot be nil")
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
	if record.LastUpdated.IsZero() {
		record.LastUpdated = time.Now()
	}

	item := map[string]types.AttributeValue{
		ddbconstant.ChainStatusFieldClientID: &types.AttributeValueMemberS{
			Value: record.ClientID,
		},
		ddbconstant.ChainStatusFieldChainSelector: &types.AttributeValueMemberN{
			Value: strconv.FormatUint(record.ChainSelector, 10),
		},
		ddbconstant.ChainStatusFieldFinalizedBlockHeight: &types.AttributeValueMemberN{
			Value: strconv.FormatUint(record.FinalizedBlockHeight, 10),
		},
		ddbconstant.ChainStatusFieldDisabled: &types.AttributeValueMemberBOOL{
			Value: record.Disabled,
		},
		ddbconstant.ChainStatusFieldLastUpdated: &types.AttributeValueMemberN{
			Value: strconv.FormatInt(record.LastUpdated.Unix(), 10),
		},
	}

	return item, nil
}

// FromItem converts a DynamoDB item to a ChainStatusRecord.
func (dto *ChainStatusDTO) FromItem(item map[string]types.AttributeValue) (*ChainStatusRecord, error) {
	if item == nil {
		return nil, fmt.Errorf("item cannot be nil")
	}

	// Extract ClientID
	clientIDAttr, ok := item[ddbconstant.ChainStatusFieldClientID].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.ChainStatusFieldClientID)
	}

	// Extract ChainSelector
	chainSelectorAttr, ok := item[ddbconstant.ChainStatusFieldChainSelector].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.ChainStatusFieldChainSelector)
	}
	chainSelector, err := strconv.ParseUint(chainSelectorAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse chain selector: %w", err)
	}

	// Extract FinalizedBlockHeight
	blockHeightAttr, ok := item[ddbconstant.ChainStatusFieldFinalizedBlockHeight].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.ChainStatusFieldFinalizedBlockHeight)
	}
	blockHeight, err := strconv.ParseUint(blockHeightAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse finalized block height: %w", err)
	}

	// Extract LastUpdated
	lastUpdatedAttr, ok := item[ddbconstant.ChainStatusFieldLastUpdated].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s field", ddbconstant.ChainStatusFieldLastUpdated)
	}
	lastUpdated, err := strconv.ParseInt(lastUpdatedAttr.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last updated: %w", err)
	}

	disabled := false
	if disabledAttr, exists := item[ddbconstant.ChainStatusFieldDisabled]; exists {
		if disabledBool, ok := disabledAttr.(*types.AttributeValueMemberBOOL); ok {
			disabled = disabledBool.Value
		}
	}

	return &ChainStatusRecord{
		ClientID:             clientIDAttr.Value,
		ChainSelector:        chainSelector,
		FinalizedBlockHeight: blockHeight,
		Disabled:             disabled,
		LastUpdated:          time.Unix(lastUpdated, 0),
	}, nil
}

// ToChainStatusMap converts a slice of ChainStatusRecord to the format expected by ChainStatusStorageInterface.
func (dto *ChainStatusDTO) ToChainStatusMap(records []*ChainStatusRecord) map[uint64]*common.ChainStatus {
	result := make(map[uint64]*common.ChainStatus, len(records))
	for _, record := range records {
		result[record.ChainSelector] = &common.ChainStatus{
			FinalizedBlockHeight: record.FinalizedBlockHeight,
			Disabled:             record.Disabled,
		}
	}
	return result
}

// FromChainStatusMap converts the ChainStatusStorageInterface format to ChainStatusRecord slice.
func (dto *ChainStatusDTO) FromChainStatusMap(clientID string, chainStatuses map[uint64]*common.ChainStatus) []*ChainStatusRecord {
	result := make([]*ChainStatusRecord, 0, len(chainStatuses))
	now := time.Now()

	for chainSelector, chainStatus := range chainStatuses {
		result = append(result, &ChainStatusRecord{
			ClientID:             clientID,
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: chainStatus.FinalizedBlockHeight,
			Disabled:             chainStatus.Disabled,
			LastUpdated:          now,
		})
	}

	return result
}
