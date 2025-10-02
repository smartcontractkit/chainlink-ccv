package ddb

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	dynamodbcontainer "github.com/testcontainers/testcontainers-go/modules/dynamodb"
)

const (
	maxRetries = 3
	retryDelay = 5 * time.Second
)

const (
	TestCommitVerificationRecordTableName = "commit_verification_records_test"
	TestFinalizedFeedTableName            = "finalized_feed_test"
	TestCheckpointTableName               = "checkpoint_storage_test"
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

// SetupTestDynamoDB creates a test DynamoDB container and client for checkpoint tests.
func SetupTestDynamoDB(t *testing.T) (*dynamodb.Client, func()) {
	ctx := context.Background()

	// Start DynamoDB Local container
	dynamoContainer, err := dynamodbcontainer.Run(ctx, "amazon/dynamodb-local:2.2.1", testcontainers.WithWaitStrategy(wait.ForHTTP("/").WithMethod("POST").WithStatusCodeMatcher(func(status int) bool {
		return status == 400
	})))
	require.NoError(t, err, "failed to start DynamoDB container")
	time.Sleep(5 * time.Second) // Wait for container to be fully ready

	// Get connection string
	connectionString, err := dynamoContainer.ConnectionString(ctx)
	require.NoError(t, err, "failed to get connection string")

	// Create AWS config for testing
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err, "failed to load AWS config")

	// Create DynamoDB client
	client := dynamodb.NewFromConfig(awsConfig, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String("http://" + connectionString)
	})

	// Create the checkpoint table
	err = CreateCheckpointTable(ctx, client, TestCheckpointTableName)
	require.NoError(t, err, "failed to create checkpoint table")

	// Create the commit verification records table
	err = CreateCommitVerificationRecordsTable(ctx, client, TestCommitVerificationRecordTableName)
	require.NoError(t, err, "failed to create commit verification records table")

	// Create the finalized feed table
	err = CreateFinalizedFeedTable(ctx, client, TestFinalizedFeedTableName)
	require.NoError(t, err, "failed to create finalized feed table")

	// Return client and cleanup function
	cleanup := func() {
		if err := dynamoContainer.Terminate(context.Background()); err != nil {
			t.Errorf("failed to terminate DynamoDB container: %v", err)
		}
	}

	return client, cleanup
}
