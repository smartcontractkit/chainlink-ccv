package ddb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	maxRetries = 3
	retryDelay = 2 * time.Second
)

// createTableWithRetry is a helper function that implements retry logic for table creation.
func createTableWithRetry(ctx context.Context, client *dynamodb.Client, input *dynamodb.CreateTableInput, tableName string) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := client.CreateTable(ctx, input)
		if err == nil {
			return nil
		}

		// Check if table already exists - this is not an error
		var resourceInUseException *types.ResourceInUseException
		if errors.As(err, &resourceInUseException) {
			return nil
		}

		lastErr = err

		// Don't wait after the last attempt
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("failed to create %s table after %d attempts: %w", tableName, maxRetries, lastErr)
}

// CreateFinalizedFeedTable creates the FinalizedFeed table for storing aggregated reports.
// This function is intended for test environments and development setup.
func CreateFinalizedFeedTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	tableInput := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(FinalizedFeedFieldCommitteeIDMessageID), // Partition Key
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(FinalizedFeedFieldFinalizedAt), // Sort Key
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(FinalizedFeedFieldCommitteeIDMessageID), // Primary Partition Key
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(FinalizedFeedFieldFinalizedAt), // Primary Sort Key
				AttributeType: types.ScalarAttributeTypeN,
			},
			{
				AttributeName: aws.String(FinalizedFeedFieldGSIPK), // GSI Partition Key
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(FinalizedFeedFieldGSISK), // GSI Sort Key
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String(GSIDayCommitteeIndex),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String(FinalizedFeedFieldGSIPK),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String(FinalizedFeedFieldGSISK),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll, // Project all attributes
				},
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	}

	return createTableWithRetry(ctx, client, tableInput, "FinalizedFeed")
}

// CreateCommitVerificationRecordsTable creates the DynamoDB table for CommitVerificationRecords.
// This function is intended for test environments and development setup.
func CreateCommitVerificationRecordsTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	input := &dynamodb.CreateTableInput{
		TableName: &tableName,
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(FieldPartitionKey), // Partition Key: CommitteeID#MessageID
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(FieldSortKey), // Sort Key: RecordType#Identifier#Timestamp
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(FieldPartitionKey),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
			{
				AttributeName: aws.String(FieldSortKey),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
		},
		BillingMode: types.BillingModePayPerRequest, // On-demand billing for tests
	}

	return createTableWithRetry(ctx, client, input, "CommitVerificationRecords")
}

// CreateCheckpointTable creates the DynamoDB table for checkpoint storage.
// This function is intended for test environments and development setup.
func CreateCheckpointTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	input := &dynamodb.CreateTableInput{
		TableName: &tableName,
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(CheckpointFieldClientID), // Partition Key: ClientID
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(CheckpointFieldChainSelector), // Sort Key: ChainSelector
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(CheckpointFieldClientID),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
			{
				AttributeName: aws.String(CheckpointFieldChainSelector),
				AttributeType: types.ScalarAttributeTypeN, // Number
			},
		},
		BillingMode: types.BillingModePayPerRequest, // On-demand billing for tests
	}

	return createTableWithRetry(ctx, client, input, "checkpoint")
}
