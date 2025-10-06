package ddb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type AccumulatorRecordDTO struct{}

func (dto *AccumulatorRecordDTO) ToItem(record *model.CommitVerificationRecord) (map[string]types.AttributeValue, error) {
	if record == nil {
		return nil, errors.New("record cannot be nil")
	}

	partitionKey := BuildPartitionKey(record.MessageId, record.CommitteeID)

	var messageData []byte
	if record.Message != nil {
		var err error
		messageData, err = proto.Marshal(record.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Message: %w", err)
		}
	}

	item := map[string]types.AttributeValue{
		FieldPartitionKey: &types.AttributeValueMemberS{Value: partitionKey},
		FieldSortKey:      &types.AttributeValueMemberS{Value: AccumulatorSortKey},

		AccumulatorFieldMessageID:             &types.AttributeValueMemberB{Value: record.GetMessageId()},
		AccumulatorFieldSourceVerifierAddress: &types.AttributeValueMemberB{Value: record.GetSourceVerifierAddress()},
		AccumulatorFieldMessage:               &types.AttributeValueMemberB{Value: messageData},
		AccumulatorFieldTimestamp:             &types.AttributeValueMemberN{Value: strconv.FormatInt(record.GetTimestamp(), 10)},
		AccumulatorFieldQuorumStatus:          &types.AttributeValueMemberS{Value: AccumulatorQuorumStatusPending},
		FieldCreatedAt:                        &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},

		// Orphan recovery fields - sparse GSI for efficient scanning
		// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
		AccumulatorFieldPendingAggregation: &types.AttributeValueMemberS{Value: GetPendingAggregationKeyForRecord(record.CommitteeID)},
	}

	if record.GetBlobData() != nil {
		item[AccumulatorFieldBlobData] = &types.AttributeValueMemberB{Value: record.GetBlobData()}
	}

	if len(record.GetReceiptBlobs()) > 0 {
		receiptBlobs := make([]types.AttributeValue, len(record.GetReceiptBlobs()))
		for i, blob := range record.GetReceiptBlobs() {
			blobData, err := proto.Marshal(blob)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ReceiptBlob[%d]: %w", i, err)
			}
			receiptBlobs[i] = &types.AttributeValueMemberB{Value: blobData}
		}
		item[AccumulatorFieldReceiptBlobs] = &types.AttributeValueMemberL{Value: receiptBlobs}
	}

	return item, nil
}

func (dto *AccumulatorRecordDTO) IsAccumulatorRecord(item map[string]types.AttributeValue) bool {
	sortKeyValue, ok := item[FieldSortKey].(*types.AttributeValueMemberS)
	if !ok {
		return false
	}
	return strings.HasPrefix(sortKeyValue.Value, AccumulatorRecordPrefix)
}
