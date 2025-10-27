package ddb

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"                                              //nolint
	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants" //nolint
	dynamodbcontainer "github.com/testcontainers/testcontainers-go/modules/dynamodb"             //nolint
)

const (
	TestCommitVerificationRecordTableName = "commit_verification_records_test"
	TestFinalizedFeedTableName            = "finalized_feed_test"
	TestChainStatusTableName               = "chain_status_storage_test"
)

// CreateFinalizedFeedTable creates the FinalizedFeed table for storing aggregated reports.
// This function is intended for test environments and development setup.
func CreateFinalizedFeedTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	tableInput := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldCommitteeIDMessageID), // Partition Key
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldFinalizedAtVerificationCountSortKey), // Sort Key
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldCommitteeIDMessageID), // Primary Partition Key
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldFinalizedAtVerificationCountSortKey), // Primary Sort Key
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldGSIPK), // GSI Partition Key
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(ddbconstant.FinalizedFeedFieldGSISK), // GSI Sort Key
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String(ddbconstant.GSIDayCommitteeIndex),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String(ddbconstant.FinalizedFeedFieldGSIPK),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String(ddbconstant.FinalizedFeedFieldGSISK),
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
	return err
}

// CreateCommitVerificationRecordsTable creates the DynamoDB table for CommitVerificationRecords.
// This function is intended for test environments and development setup.
func CreateCommitVerificationRecordsTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	input := &dynamodb.CreateTableInput{
		TableName: &tableName,
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(ddbconstant.FieldPartitionKey), // Partition Key: CommitteeID#MessageID
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(ddbconstant.FieldSortKey), // Sort Key: RecordType#Identifier#Timestamp
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(ddbconstant.FieldPartitionKey),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
			{
				AttributeName: aws.String(ddbconstant.FieldSortKey),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
			{
				AttributeName: aws.String(ddbconstant.VerificationMessageDataFieldPendingAggregation), // For orphan recovery GSI
				AttributeType: types.ScalarAttributeTypeS,                                             // String
			},
			{
				AttributeName: aws.String(ddbconstant.FieldCreatedAt), // For orphan recovery GSI sort key
				AttributeType: types.ScalarAttributeTypeN,             // Number
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String(ddbconstant.GSIPendingAggregationIndex),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String(ddbconstant.VerificationMessageDataFieldPendingAggregation), // GSI Partition Key
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String(ddbconstant.FieldCreatedAt), // GSI Sort Key
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll, // Project all attributes for orphan recovery
				},
			},
		},
		BillingMode: types.BillingModePayPerRequest, // On-demand billing for tests
	}

	_, err := client.CreateTable(ctx, input)
	return err
}

// CreateChainStatusTable creates the DynamoDB table for checkpoint storage.
// This function is intended for test environments and development setup.
func CreateChainStatusTable(ctx context.Context, client *dynamodb.Client, tableName string) error {
	input := &dynamodb.CreateTableInput{
		TableName: &tableName,
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(ddbconstant.CheckpointFieldClientID), // Partition Key: ClientID
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(ddbconstant.CheckpointFieldChainSelector), // Sort Key: ChainSelector
				KeyType:       types.KeyTypeRange,
			},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(ddbconstant.CheckpointFieldClientID),
				AttributeType: types.ScalarAttributeTypeS, // String
			},
			{
				AttributeName: aws.String(ddbconstant.CheckpointFieldChainSelector),
				AttributeType: types.ScalarAttributeTypeN, // Number
			},
		},
		BillingMode: types.BillingModePayPerRequest, // On-demand billing for tests
	}

	_, err := client.CreateTable(ctx, input)
	return err
}

// SetupTestDynamoDB creates a test DynamoDB container and client for checkpoint tests.
func SetupTestDynamoDB(t *testing.T) (*dynamodb.Client, string, func()) {
	// We retry the setup a few times to avoid transient issues with container startup.
	// This is especially useful in CI environments when port collisions can occur.
	inner := func() (*dynamodb.Client, string, func(), error) {
		ctx := context.Background()

		// Start DynamoDB Local container
		dynamoContainer, err := dynamodbcontainer.Run(ctx, "amazon/dynamodb-local:2.2.1", testcontainers.WithWaitStrategy(wait.ForHTTP("/").WithMethod("POST").WithStatusCodeMatcher(func(status int) bool {
			return status == 400
		})))
		if err != nil {
			return nil, "", nil, err
		}
		// Return client and cleanup function
		cleanup := func() {
			if err := dynamoContainer.Terminate(context.Background()); err != nil {
				t.Log("failed to terminate container:", err)
			}
		}

		// Get connection string
		connectionString, err := dynamoContainer.ConnectionString(ctx)
		if err != nil {
			cleanup()
			return nil, "", nil, err
		}

		// Create AWS config for testing
		awsConfig, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion("us-east-1"),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
		)
		if err != nil {
			cleanup()
			return nil, "", nil, err
		}

		// Create DynamoDB client
		client := dynamodb.NewFromConfig(awsConfig, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String("http://" + connectionString)
		})

		// Create the checkpoint table
		err = CreateChainStatusTable(ctx, client, TestChainStatusTableName)
		if err != nil {
			cleanup()
			return nil, "", nil, err
		}

		// Create the commit verification records table
		err = CreateCommitVerificationRecordsTable(ctx, client, TestCommitVerificationRecordTableName)
		if err != nil {
			cleanup()
			return nil, "", nil, err
		}

		// Create the finalized feed table
		err = CreateFinalizedFeedTable(ctx, client, TestFinalizedFeedTableName)
		if err != nil {
			cleanup()
			return nil, "", nil, err
		}

		return client, connectionString, cleanup, nil
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		client, connectionString, cleanup, err := inner()
		if err == nil {
			return client, connectionString, cleanup
		}
		time.Sleep(5 * time.Second)
		lastErr = err
	}
	require.NoError(t, lastErr, "failed to set up test DynamoDB after multiple attempts")
	return nil, "", nil
}
