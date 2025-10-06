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

type VerificationMessageDataRecordDTO struct{}

func (dto *VerificationMessageDataRecordDTO) ToItem(record *model.CommitVerificationRecord) (map[string]types.AttributeValue, error) {
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
		FieldSortKey:      &types.AttributeValueMemberS{Value: VerificationMessageDataSortKey},

		VerificationMessageDataFieldMessageID:             &types.AttributeValueMemberB{Value: record.GetMessageId()},
		VerificationMessageDataFieldSourceVerifierAddress: &types.AttributeValueMemberB{Value: record.GetSourceVerifierAddress()},
		VerificationMessageDataFieldMessage:               &types.AttributeValueMemberB{Value: messageData},
		VerificationMessageDataFieldTimestamp:             &types.AttributeValueMemberN{Value: strconv.FormatInt(record.GetTimestamp(), 10)},
		VerificationMessageDataFieldQuorumStatus:          &types.AttributeValueMemberS{Value: VerificationMessageDataQuorumStatusPending},
		FieldCreatedAt:                                     &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},

		// Orphan recovery fields - sparse GSI for efficient scanning
		// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
		VerificationMessageDataFieldPendingAggregation: &types.AttributeValueMemberS{Value: GetPendingAggregationKeyForRecord(record.CommitteeID)},
	}

	if record.GetBlobData() != nil {
		item[VerificationMessageDataFieldBlobData] = &types.AttributeValueMemberB{Value: record.GetBlobData()}
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
		item[VerificationMessageDataFieldReceiptBlobs] = &types.AttributeValueMemberL{Value: receiptBlobs}
	}

	return item, nil
}

func (dto *VerificationMessageDataRecordDTO) IsVerificationMessageDataRecord(item map[string]types.AttributeValue) bool {
	sortKeyValue, ok := item[FieldSortKey].(*types.AttributeValueMemberS)
	if !ok {
		return false
	}
	return strings.HasPrefix(sortKeyValue.Value, VerificationMessageDataRecordPrefix)
}