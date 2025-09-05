package handlers

import (
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

var bytes32HexStringValidation = validation.Match(regexp.MustCompile(`^[a-fA-F0-9]{64}$`))

func validateWriteRequest(req *aggregator.WriteCommitVerificationRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.CommitVerificationRecord, validation.Required))
	if err != nil {
		return err
	}

	verificationRecord := req.GetCommitVerificationRecord()

	err = validation.ValidateStruct(
		verificationRecord,
		validation.Field(&verificationRecord.MessageId, validation.Required, validation.Length(32, 32)),
		validation.Field(&verificationRecord.BlobData, validation.Required),
		validation.Field(&verificationRecord.CcvData, validation.Required),
		// TODO: Check valid selector (needs to be in our configuration)
		validation.Field(&verificationRecord.DestChainSelector, validation.Required),
		validation.Field(&verificationRecord.DestVerifierAddress, validation.Required, validation.Length(20, 20)),
		validation.Field(&verificationRecord.SequenceNumber, validation.Required),
		validation.Field(&verificationRecord.SourceChainSelector, validation.Required),
		validation.Field(&verificationRecord.SourceVerifierAddress, validation.Required, validation.Length(20, 20)),
		validation.Field(&verificationRecord.Timestamp, validation.Required),
		// TODO: Do deeper validation once format is finalized
		validation.Field(&verificationRecord.Message, validation.Required),
	)

	if err != nil {
		return err
	}
	return nil
}

func validateReadRequest(req *aggregator.ReadCommitVerificationRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.MessageId, validation.Required, validation.Length(32, 32)),
	)
	if err != nil {
		return err
	}
	return nil
}
