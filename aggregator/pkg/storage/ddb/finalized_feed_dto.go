package ddb

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type FinalizedVerification struct {
	ParticipantID string `json:"participant_id"`
	Address       []byte `json:"address"`
	SignatureR    []byte `json:"signature_r"`
	SignatureS    []byte `json:"signature_s"`
	CCVData       []byte `json:"ccv_data"`
	BlobData      []byte `json:"blob_data"`
	ReceiptBlobs  []byte `json:"receipt_blobs"`
	Timestamp     int64  `json:"timestamp"`
}

type SharedMessageData struct {
	MessageID             []byte `json:"message_id"`
	SourceVerifierAddress []byte `json:"source_verifier_address"`
	Message               []byte `json:"message"`
}

type FinalizedReport struct {
	SharedMessageData *SharedMessageData      `json:"shared_message_data"`
	Verifications     []FinalizedVerification `json:"verifications"`
}

func CommitAggregatedReportToItem(report *model.CommitAggregatedReport, shard string) (map[string]types.AttributeValue, error) {
	if report == nil {
		return nil, errors.New("report cannot be nil")
	}
	if len(report.Verifications) == 0 {
		return nil, errors.New("report must contain at least one verification")
	}

	aggregatedReportObject, err := createFinalizedReport(report)
	if err != nil {
		return nil, fmt.Errorf("failed to create finalized aggregated report: %w", err)
	}

	finalizedAt := ComputeFinalizedAt(report)

	day := FormatDay(finalizedAt)
	verificationCount := len(report.Verifications)

	pk := BuildFinalizedFeedPartitionKey(report.CommitteeID, report.MessageID)
	sk := BuildFinalizedFeedSortKey(finalizedAt)

	gsiPK := BuildGSIPartitionKey(day, report.CommitteeID, ddbconstant.FinalizedFeedVersion, shard)
	gsiSK := BuildGSISortKey(finalizedAt, verificationCount, hex.EncodeToString(report.MessageID))

	item := map[string]types.AttributeValue{
		ddbconstant.FinalizedFeedFieldCommitteeIDMessageID: &types.AttributeValueMemberS{
			Value: pk,
		},
		ddbconstant.FinalizedFeedFieldFinalizedAt: &types.AttributeValueMemberN{
			Value: sk,
		},
		ddbconstant.FinalizedFeedFieldGSIPK: &types.AttributeValueMemberS{
			Value: gsiPK,
		},
		ddbconstant.FinalizedFeedFieldGSISK: &types.AttributeValueMemberS{
			Value: gsiSK,
		},
		ddbconstant.FinalizedFeedFieldMessageID: &types.AttributeValueMemberS{
			Value: hex.EncodeToString(report.MessageID),
		},
		ddbconstant.FinalizedFeedFieldCommitteeID: &types.AttributeValueMemberS{
			Value: report.CommitteeID,
		},
		ddbconstant.FinalizedFeedFieldAggregatedReportData: &types.AttributeValueMemberM{
			Value: finalizedReportToAttributeMap(aggregatedReportObject),
		},
		ddbconstant.FinalizedFeedFieldTimestamp: &types.AttributeValueMemberN{
			Value: strconv.FormatInt(report.Timestamp, 10),
		},
	}

	return item, nil
}

func CommitAggregatedReportFromItem(item map[string]types.AttributeValue) (*model.CommitAggregatedReport, error) {
	if item == nil {
		return nil, errors.New("item cannot be nil")
	}

	messageIDValue, ok := item[ddbconstant.FinalizedFeedFieldMessageID].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("%s attribute is missing or not a string", ddbconstant.FinalizedFeedFieldMessageID)
	}

	committeeIDValue, ok := item[ddbconstant.FinalizedFeedFieldCommitteeID].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("%s attribute is missing or not a string", ddbconstant.FinalizedFeedFieldCommitteeID)
	}

	timestampValue, ok := item[ddbconstant.FinalizedFeedFieldTimestamp].(*types.AttributeValueMemberN)
	if !ok {
		return nil, fmt.Errorf("%s attribute is missing or not a number", ddbconstant.FinalizedFeedFieldTimestamp)
	}

	aggregatedReportDataValue, ok := item[ddbconstant.FinalizedFeedFieldAggregatedReportData].(*types.AttributeValueMemberM)
	if !ok {
		return nil, fmt.Errorf("%s attribute is missing or not a map", ddbconstant.FinalizedFeedFieldAggregatedReportData)
	}

	messageID, err := hex.DecodeString(messageIDValue.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MessageID from hex: %w", err)
	}

	timestamp, err := strconv.ParseInt(timestampValue.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	finalizedReport, err := attributeMapToFinalizedReport(aggregatedReportDataValue.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to convert nested object to finalized report: %w", err)
	}

	report, err := reconstructReport(finalizedReport, messageID, committeeIDValue.Value, timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct report from finalized data: %w", err)
	}

	return report, nil
}

func createFinalizedReport(report *model.CommitAggregatedReport) (*FinalizedReport, error) {
	if len(report.Verifications) == 0 {
		return nil, fmt.Errorf("report must contain at least one verification")
	}

	sourceMessage := &report.Verifications[0].MessageWithCCVNodeData

	messageBytes, err := proto.Marshal(sourceMessage.GetMessage())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	sharedMessageData := &SharedMessageData{
		MessageID:             sourceMessage.GetMessageId(),
		SourceVerifierAddress: sourceMessage.GetSourceVerifierAddress(),
		Message:               messageBytes,
	}

	// Filter out verifications with nil IdentifierSigner to avoid empty binary attributes in DynamoDB
	var validVerifications []FinalizedVerification
	for i, v := range report.Verifications {
		if v.IdentifierSigner != nil {
			var receiptBlobsBytes []byte
			if len(v.GetReceiptBlobs()) > 0 {
				for _, blob := range v.GetReceiptBlobs() {
					blobBytes, err := proto.Marshal(blob)
					if err != nil {
						return nil, fmt.Errorf("failed to marshal receipt blob for verification %d: %w", i, err)
					}
					receiptBlobsBytes = append(receiptBlobsBytes, blobBytes...)
				}
			}

			validVerifications = append(validVerifications, FinalizedVerification{
				ParticipantID: v.IdentifierSigner.ParticipantID,
				Address:       v.IdentifierSigner.Address,
				SignatureR:    v.IdentifierSigner.SignatureR[:],
				SignatureS:    v.IdentifierSigner.SignatureS[:],
				CCVData:       v.GetCcvData(),
				BlobData:      v.GetBlobData(),
				ReceiptBlobs:  receiptBlobsBytes,
				Timestamp:     v.GetTimestamp(),
			})
		}
	}

	finalized := &FinalizedReport{
		SharedMessageData: sharedMessageData,
		Verifications:     validVerifications,
	}

	if len(validVerifications) == 0 {
		return nil, fmt.Errorf("no valid verifications found after filtering out nil IdentifierSigner entries")
	}

	return finalized, nil
}

func finalizedReportToAttributeMap(report *FinalizedReport) map[string]types.AttributeValue {
	sharedMessageMap := map[string]types.AttributeValue{
		"message_id":              &types.AttributeValueMemberB{Value: report.SharedMessageData.MessageID},
		"source_verifier_address": &types.AttributeValueMemberB{Value: report.SharedMessageData.SourceVerifierAddress},
		"message":                 &types.AttributeValueMemberB{Value: report.SharedMessageData.Message},
	}

	verificationsList := make([]types.AttributeValue, len(report.Verifications))
	for i, v := range report.Verifications {
		verificationMap := map[string]types.AttributeValue{
			"participant_id": &types.AttributeValueMemberS{Value: v.ParticipantID},
			"address":        &types.AttributeValueMemberB{Value: v.Address},
			"signature_r":    &types.AttributeValueMemberB{Value: v.SignatureR},
			"signature_s":    &types.AttributeValueMemberB{Value: v.SignatureS},
			"ccv_data":       &types.AttributeValueMemberB{Value: v.CCVData},
			"receipt_blobs":  &types.AttributeValueMemberB{Value: v.ReceiptBlobs},
			"timestamp":      &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", v.Timestamp)},
		}

		// Handle BlobData - only add if not nil/empty to avoid DynamoDB validation error
		if len(v.BlobData) > 0 {
			verificationMap["blob_data"] = &types.AttributeValueMemberB{Value: v.BlobData}
		} else {
			// Use NULL attribute type for empty/nil blob data
			verificationMap["blob_data"] = &types.AttributeValueMemberNULL{Value: true}
		}

		verificationsList[i] = &types.AttributeValueMemberM{Value: verificationMap}
	}

	return map[string]types.AttributeValue{
		"shared_message_data": &types.AttributeValueMemberM{Value: sharedMessageMap},
		"verifications":       &types.AttributeValueMemberL{Value: verificationsList},
	}
}

func attributeMapToFinalizedReport(attrMap map[string]types.AttributeValue) (*FinalizedReport, error) {
	sharedMessageAttr, ok := attrMap["shared_message_data"].(*types.AttributeValueMemberM)
	if !ok {
		return nil, fmt.Errorf("shared_message_data is missing or not a map")
	}

	messageID, ok := sharedMessageAttr.Value["message_id"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("message_id is missing or not binary")
	}

	sourceVerifierAddress, ok := sharedMessageAttr.Value["source_verifier_address"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("source_verifier_address is missing or not binary")
	}

	message, ok := sharedMessageAttr.Value["message"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("message is missing or not binary")
	}

	sharedMessageData := &SharedMessageData{
		MessageID:             messageID.Value,
		SourceVerifierAddress: sourceVerifierAddress.Value,
		Message:               message.Value,
	}

	verificationsAttr, ok := attrMap["verifications"].(*types.AttributeValueMemberL)
	if !ok {
		return nil, fmt.Errorf("verifications is missing or not a list")
	}

	verifications := make([]FinalizedVerification, len(verificationsAttr.Value))
	for i, vAttr := range verificationsAttr.Value {
		vMap, ok := vAttr.(*types.AttributeValueMemberM)
		if !ok {
			return nil, fmt.Errorf("verification %d is not a map", i)
		}

		participantID, ok := vMap.Value["participant_id"].(*types.AttributeValueMemberS)
		if !ok {
			return nil, fmt.Errorf("verification %d participant_id is missing or not string", i)
		}

		address, ok := vMap.Value["address"].(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("verification %d address is missing or not binary", i)
		}

		signatureR, ok := vMap.Value["signature_r"].(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("verification %d signature_r is missing or not binary", i)
		}

		signatureS, ok := vMap.Value["signature_s"].(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("verification %d signature_s is missing or not binary", i)
		}

		ccvData, ok := vMap.Value["ccv_data"].(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("verification %d ccv_data is missing or not binary", i)
		}

		var blobDataValue []byte
		if blobDataAttr, ok := vMap.Value["blob_data"].(*types.AttributeValueMemberB); ok {
			blobDataValue = blobDataAttr.Value
		} else if _, ok := vMap.Value["blob_data"].(*types.AttributeValueMemberNULL); ok {
			blobDataValue = nil
		} else {
			return nil, fmt.Errorf("verification %d blob_data is missing or not binary/null", i)
		}

		receiptBlobs, ok := vMap.Value["receipt_blobs"].(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("verification %d receipt_blobs is missing or not binary", i)
		}

		timestampAttr, ok := vMap.Value["timestamp"].(*types.AttributeValueMemberN)
		if !ok {
			return nil, fmt.Errorf("verification %d timestamp is missing or not a number", i)
		}

		timestamp, err := strconv.ParseInt(timestampAttr.Value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("verification %d failed to parse timestamp: %w", i, err)
		}

		verifications[i] = FinalizedVerification{
			ParticipantID: participantID.Value,
			Address:       address.Value,
			SignatureR:    signatureR.Value,
			SignatureS:    signatureS.Value,
			CCVData:       ccvData.Value,
			BlobData:      blobDataValue,
			ReceiptBlobs:  receiptBlobs.Value,
			Timestamp:     timestamp,
		}
	}

	return &FinalizedReport{
		SharedMessageData: sharedMessageData,
		Verifications:     verifications,
	}, nil
}

func reconstructReport(finalizedReport *FinalizedReport, messageID []byte, committeeID string, timestamp int64) (*model.CommitAggregatedReport, error) {
	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committeeID,
		Timestamp:     timestamp,
		Verifications: make([]*model.CommitVerificationRecord, len(finalizedReport.Verifications)),
	}

	var protoMessage *pb.Message
	if len(finalizedReport.SharedMessageData.Message) > 0 {
		protoMessage = &pb.Message{}
		if err := proto.Unmarshal(finalizedReport.SharedMessageData.Message, protoMessage); err != nil {
			return nil, fmt.Errorf("failed to unmarshal protobuf message: %w", err)
		}
	}

	for i, ov := range finalizedReport.Verifications {
		var signatureR, signatureS [32]byte
		copy(signatureR[:], ov.SignatureR)
		copy(signatureS[:], ov.SignatureS)

		var receiptBlobs []*pb.ReceiptBlob
		if len(ov.ReceiptBlobs) > 0 {
			receiptBlob := &pb.ReceiptBlob{}
			if err := proto.Unmarshal(ov.ReceiptBlobs, receiptBlob); err != nil {
				receiptBlobs = []*pb.ReceiptBlob{}
			} else {
				receiptBlobs = []*pb.ReceiptBlob{receiptBlob}
			}
		}

		verification := &model.CommitVerificationRecord{
			CommitteeID: committeeID,
			IdentifierSigner: &model.IdentifierSigner{
				Signer: model.Signer{
					ParticipantID: ov.ParticipantID,
				},
				Address:     ov.Address,
				SignatureR:  signatureR,
				SignatureS:  signatureS,
				CommitteeID: committeeID,
			},
		}

		verification.MessageWithCCVNodeData = pb.MessageWithCCVNodeData{
			MessageId:             finalizedReport.SharedMessageData.MessageID,
			SourceVerifierAddress: finalizedReport.SharedMessageData.SourceVerifierAddress,
			Message:               protoMessage,
			CcvData:               ov.CCVData,
			BlobData:              ov.BlobData,
			Timestamp:             ov.Timestamp,
			ReceiptBlobs:          receiptBlobs,
		}

		report.Verifications[i] = verification
	}

	return report, nil
}
