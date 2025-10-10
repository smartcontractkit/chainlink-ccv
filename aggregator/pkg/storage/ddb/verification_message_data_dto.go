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

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
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
		ddbconstant.FieldPartitionKey: &types.AttributeValueMemberS{Value: partitionKey},
		ddbconstant.FieldSortKey:      &types.AttributeValueMemberS{Value: ddbconstant.VerificationMessageDataSortKey},

		ddbconstant.VerificationMessageDataFieldMessageID:             &types.AttributeValueMemberB{Value: record.GetMessageId()},
		ddbconstant.VerificationMessageDataFieldSourceVerifierAddress: &types.AttributeValueMemberB{Value: record.GetSourceVerifierAddress()},
		ddbconstant.VerificationMessageDataFieldMessage:               &types.AttributeValueMemberB{Value: messageData},
		ddbconstant.VerificationMessageDataFieldTimestamp:             &types.AttributeValueMemberN{Value: strconv.FormatInt(record.GetTimestamp(), 10)},
		ddbconstant.VerificationMessageDataFieldQuorumStatus:          &types.AttributeValueMemberS{Value: ddbconstant.VerificationMessageDataQuorumStatusPending},
		ddbconstant.FieldCreatedAt:                                    &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},

		// Orphan recovery fields - sparse GSI for efficient scanning
		// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
		ddbconstant.VerificationMessageDataFieldPendingAggregation: &types.AttributeValueMemberS{Value: ddbconstant.GetPendingAggregationKeyForRecord(record.CommitteeID)},
	}

	if record.GetBlobData() != nil {
		item[ddbconstant.VerificationMessageDataFieldBlobData] = &types.AttributeValueMemberB{Value: record.GetBlobData()}
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
		item[ddbconstant.VerificationMessageDataFieldReceiptBlobs] = &types.AttributeValueMemberL{Value: receiptBlobs}
	}

	return item, nil
}

func (dto *VerificationMessageDataRecordDTO) IsVerificationMessageDataRecord(item map[string]types.AttributeValue) bool {
	sortKeyValue, ok := item[ddbconstant.FieldSortKey].(*types.AttributeValueMemberS)
	if !ok {
		return false
	}
	return strings.HasPrefix(sortKeyValue.Value, ddbconstant.VerificationMessageDataRecordPrefix)
}
