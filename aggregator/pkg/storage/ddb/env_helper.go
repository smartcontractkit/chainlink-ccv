package ddb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

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

	_, err := client.CreateTable(ctx, tableInput)
	if err != nil {
		var resourceInUseException *types.ResourceInUseException
		if errors.As(err, &resourceInUseException) {
			// Table already exists, which is fine
			return nil
		}
		return fmt.Errorf("failed to create FinalizedFeed table: %w", err)
	}

	return nil
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

	_, err := client.CreateTable(ctx, input)
	if err != nil {
		var resourceInUseException *types.ResourceInUseException
		if errors.As(err, &resourceInUseException) {
			// Table already exists, which is fine
			return nil
		}
		return fmt.Errorf("failed to create CommitVerificationRecords table: %w", err)
	}

	return nil
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

	_, err := client.CreateTable(ctx, input)
	if err != nil {
		var resourceInUseException *types.ResourceInUseException
		if errors.As(err, &resourceInUseException) {
			// Table already exists, which is fine
			return nil
		}
		return fmt.Errorf("failed to create checkpoint table: %w", err)
	}

	return nil
}
