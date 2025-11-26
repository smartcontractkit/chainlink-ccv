package handlers

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func validateWriteRequest(req *pb.WriteCommitteeVerifierNodeResultRequest) error {
	err := validation.ValidateStruct(
		req,
		validation.Field(&req.CommitteeVerifierNodeResult, validation.Required))
	if err != nil {
		return err
	}

	verificationRecord := req.CommitteeVerifierNodeResult

	err = validation.ValidateStruct(
		verificationRecord,
		validation.Field(&verificationRecord.Signature, validation.Required),
		validation.Field(&verificationRecord.CcvVersion, validation.Required, validation.Length(4, 0)),
		validation.Field(&verificationRecord.Message, validation.Required),
	)
	if err != nil {
		return err
	}

	// Validate ccv_and_executor_hash is required and has correct length
	if len(verificationRecord.Message.CcvAndExecutorHash) != 32 {
		return fmt.Errorf("ccv_and_executor_hash must be exactly 32 bytes, got %d", len(verificationRecord.Message.CcvAndExecutorHash))
	}

	message, err := model.MapProtoMessageToProtocolMessage(verificationRecord.Message)
	if err != nil {
		return fmt.Errorf("failed to map proto message: %w", err)
	}
	_, err = message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}

	// Validate the hash from the verifier matches the computed hash
	ccvAddrs := make([]protocol.UnknownAddress, len(verificationRecord.CcvAddresses))
	for i, addr := range verificationRecord.CcvAddresses {
		ccvAddrs[i] = protocol.UnknownAddress(addr)
	}
	executorAddr := protocol.UnknownAddress(verificationRecord.ExecutorAddress)
	computedHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddrs, executorAddr)
	if err != nil {
		return fmt.Errorf("failed to compute CCV and executor hash: %w", err)
	}
	if message.CcvAndExecutorHash != computedHash {
		return fmt.Errorf("hash mismatch: received %x, computed %x", message.CcvAndExecutorHash, computedHash)
	}

	return nil
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
