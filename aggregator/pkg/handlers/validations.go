package handlers

import (
	"bytes"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

var hundredYears = 100 * 365 * 24 * time.Hour

func validateWriteRequest(req *pb.WriteCommitteeVerifierNodeResultRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.CcvNodeData, validation.Required))
	if err != nil {
		return err
	}

	verificationRecord := req.CcvNodeData

	err = validation.ValidateStruct(
		verificationRecord,
		validation.Field(&verificationRecord.MessageId, validation.Required, validation.Length(32, 32)),
		validation.Field(&verificationRecord.CcvData, validation.Required),
		// TODO: Check valid selector (needs to be in our configuration)
		// validation.Field(&verificationRecord.DestVerifierAddress, validation.Required, validation.Length(20, 20)),
		// validation.Field(&verificationRecord.SourceVerifierAddress, validation.Required, validation.Length(20, 20)),
		validation.Field(&verificationRecord.Timestamp, validation.Required),
		// TODO: Do deeper validation once format is finalized
		validation.Field(&verificationRecord.Message, validation.Required),
	)
	if err != nil {
		return err
	}

	message := model.MapProtoMessageToProtocolMessage(verificationRecord.Message)
	messageID, err := message.MessageID()
	if err != nil {
		return err
	}
	if !bytes.Equal(messageID[:], req.CcvNodeData.MessageId) {
		return validation.NewError("MessageId", "does not match ID derived from Message")
	}

	// Validate timestamp precision
	if !isValidMillisecondTimestamp(req.CcvNodeData.GetTimestamp()) {
		return fmt.Errorf("invalid timestamp precision")
	}

	return nil
}

// isValidMillisecondTimestamp checks if timestamp represents valid milliseconds.
func isValidMillisecondTimestamp(timestamp int64) bool {
	future := time.Now().Add(hundredYears)
	past := time.Now().Add(-hundredYears)
	return timestamp >= past.UnixMilli() && timestamp <= future.UnixMilli()
}

func validateReadRequest(req *pb.ReadCommitteeVerifierNodeResultRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.MessageId, validation.Required, validation.Length(32, 32)),
	)
	if err != nil {
		return err
	}
	return nil
}
