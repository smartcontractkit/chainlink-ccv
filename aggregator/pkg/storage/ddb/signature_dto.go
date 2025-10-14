package ddb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type SignatureRecordDTO struct{}

func (dto *SignatureRecordDTO) ToItem(record *model.CommitVerificationRecord) (map[string]types.AttributeValue, error) {
	if record == nil {
		return nil, errors.New("record cannot be nil")
	}
	if record.IdentifierSigner == nil {
		return nil, errors.New("record.IdentifierSigner cannot be nil")
	}

	signerAddressHex := common.BytesToAddress(record.IdentifierSigner.Address).Hex()

	partitionKey := BuildPartitionKey(record.MessageId, record.CommitteeID)
	sortKey := BuildSignatureSortKey(signerAddressHex, record.Timestamp)

	item := map[string]types.AttributeValue{
		ddbconstant.FieldPartitionKey: &types.AttributeValueMemberS{Value: partitionKey},
		ddbconstant.FieldSortKey:      &types.AttributeValueMemberS{Value: sortKey},

		ddbconstant.SignatureFieldSignerAddress: &types.AttributeValueMemberS{Value: signerAddressHex},
		ddbconstant.SignatureFieldParticipantID: &types.AttributeValueMemberS{Value: record.IdentifierSigner.ParticipantID},
		ddbconstant.SignatureFieldSignatureR:    &types.AttributeValueMemberB{Value: record.IdentifierSigner.SignatureR[:]},
		ddbconstant.SignatureFieldSignatureS:    &types.AttributeValueMemberB{Value: record.IdentifierSigner.SignatureS[:]},
		ddbconstant.FieldCreatedAt:              &types.AttributeValueMemberN{Value: strconv.FormatInt(record.Timestamp, 10)},
	}

	return item, nil
}

func (dto *SignatureRecordDTO) FromItem(item map[string]types.AttributeValue, messageID []byte, committeeID string, verificationMessageDataItem map[string]types.AttributeValue) (*model.CommitVerificationRecord, error) {
	if verificationMessageDataItem == nil {
		return nil, errors.New("verificationMessageDataItem is required for signature record reconstruction")
	}

	signerAddressValue, ok := item[ddbconstant.SignatureFieldSignerAddress].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.SignatureFieldSignerAddress)
	}

	participantIDValue, ok := item[ddbconstant.SignatureFieldParticipantID].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.SignatureFieldParticipantID)
	}

	signatureRValue, ok := item[ddbconstant.SignatureFieldSignatureR].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.SignatureFieldSignatureR)
	}

	signatureSValue, ok := item[ddbconstant.SignatureFieldSignatureS].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.SignatureFieldSignatureS)
	}

	var signatureR, signatureS [32]byte
	copy(signatureR[:], signatureRValue.Value)
	copy(signatureS[:], signatureSValue.Value)

	signerAddress := common.HexToAddress(signerAddressValue.Value).Bytes()

	messageWithCCVNodeData, err := dto.reconstructMessageFromVerificationMessageData(verificationMessageDataItem)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct message from verification message data: %w", err)
	}

	sigData := []protocol.Data{
		{
			R:      signatureR,
			S:      signatureS,
			Signer: common.BytesToAddress(signerAddress),
		},
	}

	ccvData, err := protocol.EncodeSignatures(sigData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures for reconstruction: %w", err)
	}
	messageWithCCVNodeData.CcvData = ccvData

	record := &model.CommitVerificationRecord{
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: participantIDValue.Value,
				Addresses:     []string{signerAddressValue.Value},
			},
			Address:     signerAddress,
			SignatureR:  signatureR,
			SignatureS:  signatureS,
			CommitteeID: committeeID,
		},
		CommitteeID: committeeID,
	}

	record.MessageWithCCVNodeData = pb.MessageWithCCVNodeData{
		MessageId:             messageWithCCVNodeData.GetMessageId(),
		SourceVerifierAddress: messageWithCCVNodeData.GetSourceVerifierAddress(),
		CcvData:               messageWithCCVNodeData.GetCcvData(),
		BlobData:              messageWithCCVNodeData.GetBlobData(),
		Timestamp:             messageWithCCVNodeData.GetTimestamp(),
		Message:               messageWithCCVNodeData.GetMessage(),
		ReceiptBlobs:          messageWithCCVNodeData.GetReceiptBlobs(),
	}

	return record, nil
}

func (dto *SignatureRecordDTO) IsSignatureRecord(item map[string]types.AttributeValue) bool {
	sortKeyValue, ok := item[ddbconstant.FieldSortKey].(*types.AttributeValueMemberS)
	if !ok {
		return false
	}
	return strings.HasPrefix(sortKeyValue.Value, ddbconstant.SignatureRecordPrefix)
}

func (dto *SignatureRecordDTO) ExtractSignerAddressFromSortKey(sortKey string) (string, error) {
	parts := strings.Split(sortKey, ddbconstant.KeySeparator)
	if len(parts) < 3 || parts[0] != ddbconstant.SignatureRecordPrefix {
		return "", fmt.Errorf("invalid signature record sort key format: %s", sortKey)
	}
	return parts[1], nil
}

func (dto *SignatureRecordDTO) reconstructMessageFromVerificationMessageData(verificationMessageDataItem map[string]types.AttributeValue) (*pb.MessageWithCCVNodeData, error) {
	messageIDValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldMessageID].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.VerificationMessageDataFieldMessageID)
	}

	sourceVerifierAddressValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldSourceVerifierAddress].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.VerificationMessageDataFieldSourceVerifierAddress)
	}

	messageValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldMessage].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.VerificationMessageDataFieldMessage)
	}

	var message pb.Message
	if err := proto.Unmarshal(messageValue.Value, &message); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Message: %w", err)
	}

	timestampValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldTimestamp].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("missing or invalid %s", ddbconstant.VerificationMessageDataFieldTimestamp)
	}

	timestamp, err := strconv.ParseInt(timestampValue.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	messageWithCCVNodeData := &pb.MessageWithCCVNodeData{
		MessageId:             messageIDValue.Value,
		SourceVerifierAddress: sourceVerifierAddressValue.Value,
		Message:               &message,
		Timestamp:             timestamp,
	}

	if blobDataValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldBlobData].(*types.AttributeValueMemberB); ok {
		messageWithCCVNodeData.BlobData = blobDataValue.Value
	}

	if receiptBlobsValue, ok := verificationMessageDataItem[ddbconstant.VerificationMessageDataFieldReceiptBlobs].(*types.AttributeValueMemberL); ok {
		receiptBlobs := make([]*pb.ReceiptBlob, len(receiptBlobsValue.Value))
		for i, blobValue := range receiptBlobsValue.Value {
			if binaryValue, ok := blobValue.(*types.AttributeValueMemberB); ok {
				var receiptBlob pb.ReceiptBlob
				if err := proto.Unmarshal(binaryValue.Value, &receiptBlob); err != nil {
					return nil, fmt.Errorf("failed to unmarshal ReceiptBlob[%d]: %w", i, err)
				}
				receiptBlobs[i] = &receiptBlob
			}
		}
		messageWithCCVNodeData.ReceiptBlobs = receiptBlobs
	}

	return messageWithCCVNodeData, nil
}
