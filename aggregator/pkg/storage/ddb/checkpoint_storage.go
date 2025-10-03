package ddb

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// CheckpointStorage provides DynamoDB-backed storage for blockchain checkpoints.
type CheckpointStorage struct {
	client     *dynamodb.Client
	tableName  string
	dto        *CheckpointDTO
	monitoring common.AggregatorMonitoring
}

// Ensure CheckpointStorage implements the interface.
var _ common.CheckpointStorageInterface = (*CheckpointStorage)(nil)

// NewCheckpointStorage creates a new DynamoDB-backed checkpoint storage instance.
func NewCheckpointStorage(client *dynamodb.Client, tableName string, monitoring common.AggregatorMonitoring) *CheckpointStorage {
	return &CheckpointStorage{
		client:     client,
		tableName:  tableName,
		dto:        &CheckpointDTO{},
		monitoring: monitoring,
	}
}

func (s *CheckpointStorage) RecordCapacity(capacity *types.ConsumedCapacity) {
	if s.monitoring != nil && capacity != nil {
		s.monitoring.Metrics().RecordCapacity(capacity)
	}
}

// StoreCheckpoints stores a batch of checkpoints for a client atomically.
// If the client doesn't exist, it will be created.
// Existing checkpoints for the same chain_selector will be overridden.
func (s *CheckpointStorage) StoreCheckpoints(ctx context.Context, clientID string, checkpoints map[uint64]uint64) error {
	if err := s.validateStoreCheckpointsInput(clientID, checkpoints); err != nil {
		return err
	}

	if len(checkpoints) == 0 {
		return nil
	}

	records := s.dto.FromCheckpointMap(clientID, checkpoints)

	transactItems := make([]types.TransactWriteItem, 0, len(records))

	for _, record := range records {
		item, err := s.dto.ToItem(record)
		if err != nil {
			return fmt.Errorf("failed to convert checkpoint to DynamoDB item: %w", err)
		}

		transactItems = append(transactItems, types.TransactWriteItem{
			Put: &types.Put{
				TableName: aws.String(s.tableName),
				Item:      item,
			},
		})
	}

	result, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems:          transactItems,
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	})

	if result != nil {
		for _, item := range result.ConsumedCapacity {
			s.RecordCapacity(&item)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to store checkpoints for client %s: %w", clientID, err)
	}

	return nil
}

// GetClientCheckpoints retrieves all checkpoints for a client.
// Returns an empty map if the client has no checkpoints.
func (s *CheckpointStorage) GetClientCheckpoints(ctx context.Context, clientID string) (map[uint64]uint64, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}

	input := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String(QueryCheckpointsByClient),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":client_id": &types.AttributeValueMemberS{Value: clientID},
		},
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	}

	result, err := s.client.Query(ctx, input)

	if result != nil {
		s.RecordCapacity(result.ConsumedCapacity)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query checkpoints for client %s: %w", clientID, err)
	}

	records := make([]*CheckpointRecord, 0, len(result.Items))
	for _, item := range result.Items {
		record, err := s.dto.FromItem(item)
		if err != nil {
			return nil, fmt.Errorf("failed to parse checkpoint record: %w", err)
		}
		records = append(records, record)
	}

	return s.dto.ToCheckpointMap(records), nil
}

// GetAllClients returns a list of all client IDs that have stored checkpoints.
// This is primarily for testing and debugging purposes.
func (s *CheckpointStorage) GetAllClients(ctx context.Context) ([]string, error) {
	// Use Scan to get all items (since we need all unique client IDs)
	// Note: This can be expensive for large datasets, but it's primarily for testing
	input := &dynamodb.ScanInput{
		TableName:              aws.String(s.tableName),
		ProjectionExpression:   aws.String(CheckpointFieldClientID),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	}

	clientSet := make(map[string]bool)
	var lastEvaluatedKey map[string]types.AttributeValue

	for {
		if lastEvaluatedKey != nil {
			input.ExclusiveStartKey = lastEvaluatedKey
		}

		result, err := s.client.Scan(ctx, input)

		if result != nil {
			s.RecordCapacity(result.ConsumedCapacity)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to scan checkpoint table: %w", err)
		}

		for _, item := range result.Items {
			clientIDAttr, ok := item[CheckpointFieldClientID].(*types.AttributeValueMemberS)
			if ok {
				clientSet[clientIDAttr.Value] = true
			}
		}

		if result.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = result.LastEvaluatedKey
	}

	clients := make([]string, 0, len(clientSet))
	for clientID := range clientSet {
		clients = append(clients, clientID)
	}

	return clients, nil
}

// validateStoreCheckpointsInput validates the input parameters for StoreCheckpoints.
func (s *CheckpointStorage) validateStoreCheckpointsInput(clientID string, checkpoints map[uint64]uint64) error {
	if clientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	if checkpoints == nil {
		return fmt.Errorf("checkpoints cannot be nil")
	}

	for chainSelector, blockHeight := range checkpoints {
		if chainSelector == 0 {
			return fmt.Errorf("chain_selector must be greater than 0")
		}
		if blockHeight == 0 {
			return fmt.Errorf("finalized_block_height must be greater than 0")
		}
	}

	return nil
}
