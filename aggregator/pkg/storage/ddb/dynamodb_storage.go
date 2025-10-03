package ddb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

type DynamoDBStorage struct {
	client                 *dynamodb.Client
	tableName              string
	finalizedFeedTableName string
	minDate                time.Time
}

var (
	_ pkgcommon.CommitVerificationStore           = (*DynamoDBStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DynamoDBStorage)(nil)
	_ pkgcommon.Sink                              = (*DynamoDBStorage)(nil)
)

func NewDynamoDBStorage(client *dynamodb.Client, tableName, finalizedFeedTableName string, minDate time.Time) *DynamoDBStorage {
	return &DynamoDBStorage{
		client:                 client,
		tableName:              tableName,
		finalizedFeedTableName: finalizedFeedTableName,
		minDate:                minDate,
	}
}

func (d *DynamoDBStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	signatureDTO := &SignatureRecordDTO{}
	accumulatorDTO := &AccumulatorRecordDTO{}

	signatureItem, err := signatureDTO.ToItem(record)
	if err != nil {
		return fmt.Errorf("failed to create signature item: %w", err)
	}

	accumulatorItem, err := accumulatorDTO.ToItem(record)
	if err != nil {
		return fmt.Errorf("failed to create accumulator item: %w", err)
	}

	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.tableName,
		Item:                signatureItem,
		ConditionExpression: aws.String(ConditionPreventDuplicateRecord),
	})
	if err != nil {
		var conditionCheckFailedException *types.ConditionalCheckFailedException
		if !errors.As(err, &conditionCheckFailedException) {
			return fmt.Errorf("failed to save signature record: %w", err)
		}
	}

	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.tableName,
		Item:                accumulatorItem,
		ConditionExpression: aws.String(ConditionPreventDuplicateAccumulator),
	})
	if err != nil {
		var conditionCheckFailedException *types.ConditionalCheckFailedException
		if !errors.As(err, &conditionCheckFailedException) {
			return fmt.Errorf("failed to save accumulator record: %w", err)
		}
	}

	return nil
}

func (d *DynamoDBStorage) getAccumulatorRecord(ctx context.Context, partitionKey string) (map[string]types.AttributeValue, error) {
	result, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(QueryRecordsByTypePrefix),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":        &types.AttributeValueMemberS{Value: partitionKey},
			":sk_prefix": &types.AttributeValueMemberS{Value: AccumulatorSortKey},
		},
		ConsistentRead: aws.Bool(false),
		Limit:          aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query accumulator record: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, nil
	}

	return result.Items[0], nil
}

func (d *DynamoDBStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	signatureDTO := &SignatureRecordDTO{}
	signerAddressHex := common.BytesToAddress(id.Address).Hex()
	partitionKey := BuildPartitionKey(id.MessageID, id.CommitteeID)

	accumulatorRecord, err := d.getAccumulatorRecord(ctx, partitionKey)
	if err != nil {
		return nil, err
	}

	signatureResult, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(QuerySignatureRecordsBySigner),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":        &types.AttributeValueMemberS{Value: partitionKey},
			":sk_prefix": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s#%s#", SignatureRecordPrefix, signerAddressHex)},
		},
		ConsistentRead:   aws.Bool(false),
		Limit:            aws.Int32(1),
		ScanIndexForward: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query signature record: %w", err)
	}

	if len(signatureResult.Items) == 0 {
		return nil, fmt.Errorf("commit verification record not found")
	}

	record, err := signatureDTO.FromItem(signatureResult.Items[0], id.MessageID, id.CommitteeID, accumulatorRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature record: %w", err)
	}

	return record, nil
}

func (d *DynamoDBStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	signatureDTO := &SignatureRecordDTO{}
	accumulatorDTO := &AccumulatorRecordDTO{}
	partitionKey := BuildPartitionKey(messageID, committee)

	result, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(QueryAllRecordsInPartition),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: partitionKey},
		},
		ConsistentRead: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}

	records := make([]*model.CommitVerificationRecord, 0, len(result.Items))
	var accumulatorItem map[string]types.AttributeValue

	for _, item := range result.Items {
		if accumulatorDTO.IsAccumulatorRecord(item) {
			accumulatorItem = item
			break
		}
	}

	for _, item := range result.Items {
		if !signatureDTO.IsSignatureRecord(item) {
			continue
		}

		record, err := signatureDTO.FromItem(item, messageID, committee, accumulatorItem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature record: %w", err)
		}

		records = append(records, record)
	}

	return records, nil
}

func (d *DynamoDBStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}
	if len(report.Verifications) == 0 {
		return fmt.Errorf("report must contain at least one verification")
	}

	finalizedFeedDTO := &FinalizedFeedDTO{}

	finalizedFeedRecord, err := finalizedFeedDTO.ToItem(report)
	if err != nil {
		return fmt.Errorf("failed to map aggregated report to FinalizedFeed item: %w", err)
	}

	// First, submit the finalized feed record
	putInput := &dynamodb.PutItemInput{
		TableName:           aws.String(d.finalizedFeedTableName),
		Item:                finalizedFeedRecord,
		ConditionExpression: aws.String(ConditionPreventDuplicateFinalizedFeed),
	}

	_, err = d.client.PutItem(ctx, putInput)
	if err != nil {
		var conditionalCheckFailedException *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckFailedException) {
			return nil
		}
		return fmt.Errorf("failed to submit report to FinalizedFeed table: %w", err)
	}

	// Now remove the PendingAggregation field from the accumulator record to mark it as no longer orphaned
	err = d.markAccumulatorAsAggregated(ctx, report.MessageID, report.CommitteeID)
	if err != nil {
		// Log error but don't fail the entire operation since the report was already saved
		// This is a best-effort cleanup operation
		fmt.Printf("Warning: failed to mark accumulator as aggregated for messageID %x, committee %s: %v\n",
			report.MessageID, report.CommitteeID, err)
	}

	return nil
}

// markAccumulatorAsAggregated removes the PendingAggregation field from the accumulator record.
func (d *DynamoDBStorage) markAccumulatorAsAggregated(ctx context.Context, messageID model.MessageID, committeeID string) error {
	partitionKey := BuildPartitionKey(messageID, committeeID)

	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			FieldPartitionKey: &types.AttributeValueMemberS{Value: partitionKey},
			FieldSortKey:      &types.AttributeValueMemberS{Value: AccumulatorSortKey},
		},
		UpdateExpression: aws.String("REMOVE " + AccumulatorFieldPendingAggregation +
			" SET " + AccumulatorFieldQuorumStatus + " = :status"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: "AGGREGATED"},
		},
		// Only update if the record exists
		ConditionExpression: aws.String("attribute_exists(" + FieldPartitionKey + ")"),
	}

	_, err := d.client.UpdateItem(ctx, updateInput)
	if err != nil {
		var conditionalCheckFailedException *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckFailedException) {
			// Record doesn't exist or was already updated - this is fine
			return nil
		}
		return fmt.Errorf("failed to update accumulator record: %w", err)
	}

	return nil
}

func (d *DynamoDBStorage) QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string) ([]*model.CommitAggregatedReport, error) {
	if start > end {
		return nil, fmt.Errorf("start time (%d) cannot be greater than end time (%d)", start, end)
	}

	var allReports []*model.CommitAggregatedReport

	dayIterator := NewDayIterator(start, end, d.minDate)

	for dayIterator.Next() {
		day := dayIterator.Day()

		gsiPK := BuildGSIPartitionKey(day, committeeID, FinalizedFeedVersion, FinalizedFeedShard)

		dayReports, err := d.queryFinalizedFeedByGSI(ctx, gsiPK, start, end)
		if err != nil {
			return nil, fmt.Errorf("failed to query day %s: %w", day, err)
		}

		allReports = append(allReports, dayReports...)
		dayIterator.Advance()
	}

	return allReports, nil
}

func (d *DynamoDBStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	pk := BuildFinalizedFeedPartitionKey(committeeID, messageID)

	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(d.finalizedFeedTableName),
		KeyConditionExpression: aws.String(QueryLatestReportByCommitteeMessage),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{
				Value: pk,
			},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}

	result, err := d.client.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("failed to query for committeeID %s and messageID %s: %w", committeeID, hex.EncodeToString(messageID), err)
	}

	if len(result.Items) == 0 {
		return nil, nil
	}

	finalizedFeedDTO := &FinalizedFeedDTO{}

	report, err := finalizedFeedDTO.FromItem(result.Items[0])
	if err != nil {
		return nil, fmt.Errorf("failed to map FinalizedFeed item to aggregated report: %w", err)
	}

	return report, nil
}

func (d *DynamoDBStorage) queryFinalizedFeedByGSI(ctx context.Context, gsiPK string, startSeconds, endSeconds int64) ([]*model.CommitAggregatedReport, error) {
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(d.finalizedFeedTableName),
		IndexName:              aws.String(GSIDayCommitteeIndex),
		KeyConditionExpression: aws.String(QueryReportsInDayCommitteeRange),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":gsiPK": &types.AttributeValueMemberS{
				Value: gsiPK,
			},
			":startKey": &types.AttributeValueMemberS{
				Value: fmt.Sprintf("%010d#", startSeconds),
			},
			":endKey": &types.AttributeValueMemberS{
				Value: fmt.Sprintf("%010d#ZZZZZ", endSeconds),
			},
		},
		ScanIndexForward: aws.Bool(true),
	}

	result, err := d.client.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("failed to query FinalizedFeed GSI partition %s: %w", gsiPK, err)
	}

	finalizedFeedDTO := &FinalizedFeedDTO{}
	reports := make([]*model.CommitAggregatedReport, 0, len(result.Items))
	for _, item := range result.Items {
		report, err := finalizedFeedDTO.FromItem(item)
		if err != nil {
			return nil, fmt.Errorf("failed to map FinalizedFeed item to aggregated report: %w", err)
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (d *DynamoDBStorage) ListOrphanedMessageIds(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	resultChan := make(chan model.MessageID, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		queryInput := &dynamodb.QueryInput{
			TableName:              aws.String(d.tableName),
			IndexName:              aws.String(GSIPendingAggregationIndex),
			KeyConditionExpression: aws.String(fmt.Sprintf("%s = :gsiPK", AccumulatorFieldPendingAggregation)),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gsiPK": &types.AttributeValueMemberS{Value: GetPendingAggregationKeyForRecord(committeeID)},
			},
		}

		var lastEvaluatedKey map[string]types.AttributeValue
		accumulatorDTO := &AccumulatorRecordDTO{}

		for {
			if lastEvaluatedKey != nil {
				queryInput.ExclusiveStartKey = lastEvaluatedKey
			}

			result, err := d.client.Query(ctx, queryInput)
			if err != nil {
				select {
				case errorChan <- fmt.Errorf("failed to scan orphaned records: %w", err):
				case <-ctx.Done():
				}
				return
			}

			// Process results
			for _, item := range result.Items {
				if !accumulatorDTO.IsAccumulatorRecord(item) {
					continue // Skip non-accumulator records
				}

				// Extract MessageID and CommitteeID from the item directly
				messageID, err := d.extractMessageIDFromItem(item)
				if err != nil {
					select {
					case errorChan <- fmt.Errorf("failed to extract MessageID: %w", err):
					case <-ctx.Done():
					}
					return
				}

				select {
				case resultChan <- messageID:
				case <-ctx.Done():
					return
				}
			}

			// Check if we need to continue pagination
			if result.LastEvaluatedKey == nil {
				break
			}
			lastEvaluatedKey = result.LastEvaluatedKey
		}
	}()

	return resultChan, errorChan
}

// extractMessageIDFromItem extracts the MessageID from a DynamoDB item.
func (d *DynamoDBStorage) extractMessageIDFromItem(item map[string]types.AttributeValue) (model.MessageID, error) {
	messageIDValue, ok := item[AccumulatorFieldMessageID].(*types.AttributeValueMemberB)
	if !ok {
		return nil, errors.New("MessageID field not found or wrong type")
	}
	return model.MessageID(messageIDValue.Value), nil
}

// extractCommitteeIDFromItem extracts the CommitteeID from the partition key.
func (d *DynamoDBStorage) extractCommitteeIDFromItem(item map[string]types.AttributeValue) (string, error) {
	partitionKeyValue, ok := item[FieldPartitionKey].(*types.AttributeValueMemberS)
	if !ok {
		return "", errors.New("PartitionKey field not found or wrong type")
	}

	// Parse the partition key format: "committee#messageID"
	parts := strings.Split(partitionKeyValue.Value, KeySeparator)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid partition key format: %s", partitionKeyValue.Value)
	}

	return parts[0], nil
}
