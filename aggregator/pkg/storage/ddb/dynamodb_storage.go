package ddb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/query"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

type DynamoDBStorage struct {
	client                 *dynamodb.Client
	tableName              string
	finalizedFeedTableName string
	minDate                time.Time
	lggr                   logger.SugaredLogger
	monitoring             pkgcommon.AggregatorMonitoring
	pageSize               int
	shardCount             int
	timeProvider           pkgcommon.TimeProvider
}

var (
	_ pkgcommon.CommitVerificationStore           = (*DynamoDBStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DynamoDBStorage)(nil)
	_ pkgcommon.Sink                              = (*DynamoDBStorage)(nil)
)

func NewDynamoDBStorage(client *dynamodb.Client, tableName, finalizedFeedTableName string, minDate time.Time, logger logger.SugaredLogger, monitoring pkgcommon.AggregatorMonitoring, pageSize, shardCount int) *DynamoDBStorage {
	return NewDynamoDBStorageWithTimeProvider(client, tableName, finalizedFeedTableName, minDate, logger, monitoring, pageSize, shardCount, pkgcommon.NewRealTimeProvider())
}

func NewDynamoDBStorageWithTimeProvider(client *dynamodb.Client, tableName, finalizedFeedTableName string, minDate time.Time, logger logger.SugaredLogger, monitoring pkgcommon.AggregatorMonitoring, pageSize, shardCount int, timeProvider pkgcommon.TimeProvider) *DynamoDBStorage {
	return &DynamoDBStorage{
		client:                 client,
		tableName:              tableName,
		finalizedFeedTableName: finalizedFeedTableName,
		minDate:                minDate,
		lggr:                   logger,
		monitoring:             monitoring,
		pageSize:               pageSize,
		shardCount:             shardCount,
		timeProvider:           timeProvider,
	}
}

func (d *DynamoDBStorage) RecordCapacity(capacity *types.ConsumedCapacity) {
	if d.monitoring != nil && capacity != nil {
		d.monitoring.Metrics().RecordCapacity(capacity)
	}
}

func (d *DynamoDBStorage) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, d.lggr)
}

func (d *DynamoDBStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	signatureDTO := &SignatureRecordDTO{}
	verificationMessageDataDTO := &VerificationMessageDataRecordDTO{}

	signatureItem, err := signatureDTO.ToItem(record)
	if err != nil {
		return fmt.Errorf("failed to create signature item: %w", err)
	}

	verificationMessageDataItem, err := verificationMessageDataDTO.ToItem(record)
	if err != nil {
		return fmt.Errorf("failed to create verification message data item: %w", err)
	}

	output, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.tableName,
		Item:                signatureItem,
		ConditionExpression: aws.String(ddbconstant.ConditionPreventDuplicateRecord),
	})

	if output != nil {
		d.RecordCapacity(output.ConsumedCapacity)
	}

	if err != nil {
		var conditionCheckFailedException *types.ConditionalCheckFailedException
		if !errors.As(err, &conditionCheckFailedException) {
			return fmt.Errorf("failed to save signature record: %w", err)
		}
	}

	output, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:              &d.tableName,
		Item:                   verificationMessageDataItem,
		ConditionExpression:    aws.String(ddbconstant.ConditionPreventDuplicateVerificationMessageData),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	})

	if output != nil {
		d.RecordCapacity(output.ConsumedCapacity)
	}

	if err != nil {
		var conditionCheckFailedException *types.ConditionalCheckFailedException
		if !errors.As(err, &conditionCheckFailedException) {
			return fmt.Errorf("failed to save verification message data record: %w", err)
		}
	}

	return nil
}

func (d *DynamoDBStorage) getVerificationMessageDataRecord(ctx context.Context, partitionKey string) (map[string]types.AttributeValue, error) {
	result, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(ddbconstant.QueryRecordsByTypePrefix),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":        &types.AttributeValueMemberS{Value: partitionKey},
			":sk_prefix": &types.AttributeValueMemberS{Value: ddbconstant.VerificationMessageDataSortKey},
		},
		ConsistentRead:         aws.Bool(false),
		Limit:                  aws.Int32(1),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	})

	if result != nil {
		d.RecordCapacity(result.ConsumedCapacity)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query verification message data record: %w", err)
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

	verificationMessageDataRecord, err := d.getVerificationMessageDataRecord(ctx, partitionKey)
	if err != nil {
		return nil, err
	}

	signatureResult, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(ddbconstant.QuerySignatureRecordsBySigner),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":        &types.AttributeValueMemberS{Value: partitionKey},
			":sk_prefix": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s#%s#", ddbconstant.SignatureRecordPrefix, signerAddressHex)},
		},
		ConsistentRead:         aws.Bool(false),
		Limit:                  aws.Int32(1),
		ScanIndexForward:       aws.Bool(false),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	})

	if signatureResult != nil {
		d.RecordCapacity(signatureResult.ConsumedCapacity)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query signature record: %w", err)
	}

	if len(signatureResult.Items) == 0 {
		return nil, fmt.Errorf("commit verification record not found")
	}

	record, err := signatureDTO.FromItem(signatureResult.Items[0], id.MessageID, id.CommitteeID, verificationMessageDataRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature record: %w", err)
	}

	return record, nil
}

func (d *DynamoDBStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	signatureDTO := &SignatureRecordDTO{}
	verificationMessageDataDTO := &VerificationMessageDataRecordDTO{}
	partitionKey := BuildPartitionKey(messageID, committee)

	result, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.tableName,
		KeyConditionExpression: aws.String(ddbconstant.QueryAllRecordsInPartition),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: partitionKey},
		},
		ConsistentRead:         aws.Bool(true),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	})

	if result != nil {
		d.RecordCapacity(result.ConsumedCapacity)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}

	records := make([]*model.CommitVerificationRecord, 0, len(result.Items))
	var verificationMessageDataItem map[string]types.AttributeValue

	for _, item := range result.Items {
		if verificationMessageDataDTO.IsVerificationMessageDataRecord(item) {
			verificationMessageDataItem = item
			break
		}
	}

	for _, item := range result.Items {
		if !signatureDTO.IsSignatureRecord(item) {
			continue
		}

		record, err := signatureDTO.FromItem(item, messageID, committee, verificationMessageDataItem)
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

	// Set the write timestamp - this represents when the report is being stored
	// This ensures GetMessagesSince returns items in storage order, not verification order
	report.WrittenAt = d.timeProvider.Now().Unix()
	report.Sequence = report.WrittenAt

	// Calculate shard based on messageID and shardCount
	shard := ddbconstant.CalculateShardFromMessageID(report.MessageID, d.shardCount)

	finalizedFeedRecord, err := CommitAggregatedReportToItem(report, shard)
	if err != nil {
		return fmt.Errorf("failed to map aggregated report to FinalizedFeed item: %w", err)
	}

	// First, submit the finalized feed record
	putInput := &dynamodb.PutItemInput{
		TableName:              aws.String(d.finalizedFeedTableName),
		Item:                   finalizedFeedRecord,
		ConditionExpression:    aws.String(ddbconstant.ConditionPreventDuplicateFinalizedFeed),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	}

	output, err := d.client.PutItem(ctx, putInput)
	if output != nil {
		d.RecordCapacity(output.ConsumedCapacity)
	}
	if err != nil {
		var conditionalCheckFailedException *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckFailedException) {
			d.logger(ctx).Infow("Duplicate report detected, skipping write", "verifications", len(report.Verifications))
			return nil
		}
		return fmt.Errorf("failed to submit report to FinalizedFeed table: %w", err)
	}

	// Now remove the PendingAggregation field from the verification message data record to mark it as no longer orphaned
	err = d.markVerificationMessageDataAsAggregated(ctx, report.MessageID, report.CommitteeID)
	if err != nil {
		// Log error but don't fail the entire operation since the report was already saved
		// This is a best-effort cleanup operation
		d.logger(ctx).Warnf("failed to mark verification message data as aggregated: %v", err)
	}

	return nil
}

// markVerificationMessageDataAsAggregated removes the PendingAggregation field from the verification message data record.
func (d *DynamoDBStorage) markVerificationMessageDataAsAggregated(ctx context.Context, messageID model.MessageID, committeeID string) error {
	partitionKey := BuildPartitionKey(messageID, committeeID)

	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			ddbconstant.FieldPartitionKey: &types.AttributeValueMemberS{Value: partitionKey},
			ddbconstant.FieldSortKey:      &types.AttributeValueMemberS{Value: ddbconstant.VerificationMessageDataSortKey},
		},
		UpdateExpression: aws.String("REMOVE " + ddbconstant.VerificationMessageDataFieldPendingAggregation +
			" SET " + ddbconstant.VerificationMessageDataFieldQuorumStatus + " = :status"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: "AGGREGATED"},
		},
		// Only update if the record exists
		ConditionExpression: aws.String("attribute_exists(" + ddbconstant.FieldPartitionKey + ")"),
	}

	_, err := d.client.UpdateItem(ctx, updateInput)
	if err != nil {
		var conditionalCheckFailedException *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckFailedException) {
			// Record doesn't exist or was already updated - this is fine
			return nil
		}
		return fmt.Errorf("failed to update verification message data record: %w", err)
	}

	return nil
}

func (d *DynamoDBStorage) shardQueryIteratorForDay(
	gsiPK string,
	start, end int64,
	pagination *query.SinglePartitionPaginationToken,
	singleShardPageSize int32,
) *query.Iterator {
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(d.finalizedFeedTableName),
		IndexName:                 aws.String(ddbconstant.GSIDayCommitteeIndex),
		KeyConditionExpression:    aws.String(fmt.Sprintf("%s = :pk", ddbconstant.FinalizedFeedFieldGSIPK)),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: gsiPK}, ":start": &types.AttributeValueMemberN{Value: strconv.FormatInt(start, 10)}, ":end": &types.AttributeValueMemberN{Value: strconv.FormatInt(end, 10)}},
		FilterExpression:          aws.String(fmt.Sprintf("%s BETWEEN :start AND :end", ddbconstant.FinalizedFeedFieldWrittenAt)),
		ScanIndexForward:          aws.Bool(true),
		ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
	}
	if pagination != nil {
		in.ExclusiveStartKey = pagination.ToExclusiveStartKey()
	}

	it := query.NewIterator(d.client, in, d.monitoring)
	it.SetPageLimit(singleShardPageSize)
	return it
}

func (d *DynamoDBStorage) QueryAggregatedReports(
	ctx context.Context,
	start int64,
	committeeID string,
	paginationToken *string,
) (*model.PaginatedAggregatedReports, error) {
	end := time.Now().Unix()
	return d.QueryAggregatedReportsRange(ctx, start, end, committeeID, paginationToken)
}

func (d *DynamoDBStorage) QueryAggregatedReportsRange(
	ctx context.Context,
	start, end int64,
	committeeID string,
	paginationToken *string,
) (*model.PaginatedAggregatedReports, error) {
	if start > end {
		return nil, fmt.Errorf("start time (%d) cannot be greater than end time (%d)", start, end)
	}

	pageSize := d.pageSize
	pagedResults := make([]*model.CommitAggregatedReport, 0, pageSize)

	inTok, err := query.ParsePaginationToken(paginationToken)
	if err != nil {
		return nil, err
	}

	shards := ddbconstant.CreateShardIDs(d.shardCount)
	// Calculate page size per shard with overflow protection
	pagePerShard := (pageSize / len(shards)) + 1
	if pagePerShard > int(^uint32(0)>>1) {
		pagePerShard = int(^uint32(0) >> 1) // Max int32 value
	}
	singleShardPageSize := int32(pagePerShard) //nolint:gosec // overflow protection added above

	shardIteratorFactory := func(day, shard string, prev *query.SinglePartitionPaginationToken) query.ItemIterator {
		gsiPK := BuildGSIPartitionKey(day, committeeID, ddbconstant.FinalizedFeedVersion, shard)
		return d.shardQueryIteratorForDay(gsiPK, start, end, prev, singleShardPageSize)
	}

	di := query.NewDynamoAggregatedReportFeedIterator(
		start, end, d.minDate, inTok,
		shards,
		shardIteratorFactory,
	)

	for len(pagedResults) < pageSize && di.Next(ctx) {
		item := di.Item()
		ff, err := CommitAggregatedReportFromItem(item)
		if err != nil {
			return nil, fmt.Errorf("decode item: %w", err)
		}
		pagedResults = append(pagedResults, ff)
	}
	if err := di.Err(); err != nil {
		return nil, err
	}

	nextPaginationToken := di.NextPageToken()

	nextTokenStr, err := query.SerializePaginationToken(nextPaginationToken)
	if err != nil {
		return nil, err
	}

	return &model.PaginatedAggregatedReports{
		Reports:       pagedResults,
		NextPageToken: nextTokenStr,
	}, nil
}

func (d *DynamoDBStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	pk := BuildFinalizedFeedPartitionKey(committeeID, messageID)

	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(d.finalizedFeedTableName),
		KeyConditionExpression: aws.String(ddbconstant.QueryLatestReportByCommitteeMessage),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{
				Value: pk,
			},
		},
		ScanIndexForward:       aws.Bool(false),
		Limit:                  aws.Int32(10),
		ReturnConsumedCapacity: types.ReturnConsumedCapacityIndexes,
	}

	result, err := d.client.Query(ctx, queryInput)
	if result != nil {
		d.RecordCapacity(result.ConsumedCapacity)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query for committeeID %s and messageID %s: %w", committeeID, hex.EncodeToString(messageID), err)
	}

	if len(result.Items) == 0 {
		return nil, nil
	}

	report, err := CommitAggregatedReportFromItem(result.Items[0])
	if err != nil {
		return nil, fmt.Errorf("failed to map FinalizedFeed item to aggregated report: %w", err)
	}

	return report, nil
}

func (d *DynamoDBStorage) ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	resultChan := make(chan model.MessageID, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		queryInput := &dynamodb.QueryInput{
			TableName:              aws.String(d.tableName),
			IndexName:              aws.String(ddbconstant.GSIPendingAggregationIndex),
			KeyConditionExpression: aws.String(fmt.Sprintf("%s = :gsiPK", ddbconstant.VerificationMessageDataFieldPendingAggregation)),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gsiPK": &types.AttributeValueMemberS{Value: ddbconstant.GetPendingAggregationKeyForRecord(committeeID)},
			},
		}

		var lastEvaluatedKey map[string]types.AttributeValue
		verificationMessageDataDTO := &VerificationMessageDataRecordDTO{}

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
				if !verificationMessageDataDTO.IsVerificationMessageDataRecord(item) {
					continue // Skip non-verification message data records
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
	messageIDValue, ok := item[ddbconstant.VerificationMessageDataFieldMessageID].(*types.AttributeValueMemberB)
	if !ok {
		return nil, errors.New("MessageID field not found or wrong type")
	}
	return messageIDValue.Value, nil
}
