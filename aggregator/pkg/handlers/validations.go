package handlers

import (
	"bytes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func validateWriteRequest(req *aggregator.WriteCommitCCVNodeDataRequest) error {
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
		validation.Field(&verificationRecord.BlobData, validation.Required),
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

	return nil
}

func validateReadRequest(req *aggregator.ReadCommitCCVNodeDataRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.MessageId, validation.Required, validation.Length(32, 32)),
	)
	if err != nil {
		return err
	}
	return nil
}
