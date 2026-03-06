package handlers

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func validateWriteRequest(req *committeepb.WriteCommitteeVerifierNodeResultRequest) error {
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

	if err := validateAddressBounds(verificationRecord); err != nil {
		return err
	}

	// Validate ccv_and_executor_hash is required and has correct length
	if len(verificationRecord.Message.CcvAndExecutorHash) != 32 {
		return fmt.Errorf("ccv_and_executor_hash must be exactly 32 bytes, got %d", len(verificationRecord.Message.CcvAndExecutorHash))
	}

	message, err := ccvcommon.MapProtoMessageToProtocolMessage(verificationRecord.Message)
	if err != nil {
		return fmt.Errorf("failed to map proto message: %w", err)
	}

	if message.SourceChainSelector == message.DestChainSelector {
		return fmt.Errorf("source_chain_selector and dest_chain_selector cannot be equal")
	}

	_, err = message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}

	if len(verificationRecord.CcvAddresses) == 0 {
		return fmt.Errorf("ccv_addresses cannot be empty")
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

func validateAddressBounds(record *committeepb.CommitteeVerifierNodeResult) error {
	for i, addr := range record.CcvAddresses {
		if len(addr) > protocol.MaxUnknownAddressBytes {
			return fmt.Errorf("ccv_addresses[%d] size %d bytes exceeds maximum %d", i, len(addr), protocol.MaxUnknownAddressBytes)
		}
	}

	if len(record.ExecutorAddress) > protocol.MaxUnknownAddressBytes {
		return fmt.Errorf("executor_address size %d bytes exceeds maximum %d", len(record.ExecutorAddress), protocol.MaxUnknownAddressBytes)
	}

	return nil
}

func validateReadRequest(req *committeepb.ReadCommitteeVerifierNodeResultRequest) error {
	return validation.ValidateStruct(
		req,
		validation.Field(&req.MessageId, validation.Required, validation.Length(32, 32)),
		validation.Field(&req.Address, validation.Required),
	)
}
