package cctp

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AttestationService interface {
	// Fetch retrieves the attestation for a given transaction hash and message.
	Fetch(ctx context.Context, txHash protocol.ByteSlice, message protocol.Message) (Attestation, error)
}

// Attestation represents a CCTP attestation along with related data
// allowing creating proper payload for the verifier on the destination chain.
type Attestation struct {
	ccvVerifierVersion protocol.ByteSlice
	ccvAddress         protocol.UnknownAddress
	attestation        protocol.ByteSlice
	encodedCCTPMessage protocol.ByteSlice
}

func NewAttestation(
	ccvVerifierVersion protocol.ByteSlice,
	msg Message,
) (Attestation, error) {
	attestation, err := msg.DecodeAttestation()
	if err != nil {
		return Attestation{}, fmt.Errorf("failed to decode attestation: %w", err)
	}
	encodedCCTPMessage, err := protocol.NewByteSliceFromHex(msg.Message)
	if err != nil {
		return Attestation{}, fmt.Errorf("failed to decode CCTP message: %w", err)
	}
	ccvAddress, err := protocol.NewUnknownAddressFromHex(msg.DecodedMessage.Sender)
	if err != nil {
		return Attestation{}, fmt.Errorf("failed to decode CCV address: %w", err)
	}

	return Attestation{
		ccvVerifierVersion: ccvVerifierVersion,
		ccvAddress:         ccvAddress,
		attestation:        attestation,
		encodedCCTPMessage: encodedCCTPMessage,
	}, nil
}

// ToVerifierFormat converts the message into protocol.ByteSlice expected
// by the verifier on the destination chain
// format: <4 byte verifier version><encoded CCTP message><attestation>.
func (a *Attestation) ToVerifierFormat() protocol.ByteSlice {
	var output protocol.ByteSlice
	output = append(output, a.ccvVerifierVersion...)
	output = append(output, a.encodedCCTPMessage...)
	output = append(output, a.attestation...)
	return output
}

type HTTPAttestationService struct {
	lggr               logger.Logger
	client             HTTPClient
	ccvVerifierVersion protocol.ByteSlice
	ccvAddresses       map[protocol.ChainSelector]protocol.UnknownAddress
}

func NewAttestationService(
	lggr logger.Logger,
	config CCTPConfig,
) (AttestationService, error) {
	client, err := NewHTTPClient(lggr, config)
	if err != nil {
		return nil, err
	}
	return &HTTPAttestationService{
		lggr:               lggr,
		client:             client,
		ccvVerifierVersion: ccvVerifierVersion,
		ccvAddresses:       config.ParsedVerifiers,
	}, nil
}

// Fetch calls CCTP Attestation API using sourceChainDomain + txHash
// It iterates through results to find the attestation for matching message
// We use hookData and sender address to match the message against the protocol.Message.
func (h *HTTPAttestationService) Fetch(
	ctx context.Context,
	txHash protocol.ByteSlice,
	message protocol.Message,
) (Attestation, error) {
	sourceDomain, ok := sourceDomains[uint64(message.SourceChainSelector)]
	if !ok {
		return Attestation{}, fmt.Errorf("unsupported source chain selector: %d", message.SourceChainSelector)
	}

	response, err := h.client.GetMessages(ctx, message.SourceChainSelector, sourceDomain, txHash.String())
	if err != nil {
		return Attestation{}, fmt.Errorf(
			"error fetching messages for chain selector %d and tx hash %s: %s",
			message.SourceChainSelector, txHash, err,
		)
	}
	return h.extractAttestationFromResponse(response, message)
}

func (h *HTTPAttestationService) extractAttestationFromResponse(response Messages, message protocol.Message) (Attestation, error) {
	for _, msg := range response.Messages {
		err := cctpMatchesMessage(h.ccvVerifierVersion, h.ccvAddresses, msg, message)
		if err != nil {
			h.lggr.Debugw(
				"skipping CCTP message as it doesn't match CCIP message",
				"message", msg,
				"reason", err,
			)
			continue
		}
		if msg.IsAttestationComplete() {
			return NewAttestation(h.ccvVerifierVersion, msg)
		}
		return Attestation{}, fmt.Errorf("attestation is not ready")
	}
	return Attestation{}, fmt.Errorf("no matching message found in response")
}

func cctpMatchesMessage(
	ccvVerifierVersion protocol.ByteSlice,
	ccvAddresses map[protocol.ChainSelector]protocol.UnknownAddress,
	cctpMessage Message,
	ccipMessage protocol.Message,
) error {
	messageID, err := ccipMessage.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}

	if !cctpMessage.IsV2() {
		return fmt.Errorf("unsupported CCTP version")
	}

	ccvAddress, ok := ccvAddresses[ccipMessage.SourceChainSelector]
	if !ok {
		return fmt.Errorf("no CCV address configured for source chain selector: %s", ccipMessage.SourceChainSelector)
	}

	senderAddress, err := protocol.NewUnknownAddressFromHex(cctpMessage.DecodedMessage.Sender)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	if !ccvAddress.Equal(senderAddress) {
		return fmt.Errorf("sender address mismatch: expected %s, got %s", ccvAddress.String(), senderAddress.String())
	}

	actualHookData, err := protocol.NewByteSliceFromHex(cctpMessage.DecodedMessage.DecodedMessageBody.HookData)
	if err != nil {
		return fmt.Errorf("invalid hook data: %w", err)
	}

	// <4 byte verifier version><32 byte msg ID>
	var expectedHookData protocol.ByteSlice
	expectedHookData = append(expectedHookData, ccvVerifierVersion...)
	expectedHookData = append(expectedHookData, messageID[:]...)
	if actualHookData.String() != expectedHookData.String() {
		return fmt.Errorf("hook data mismatch: expected %s, got %s", expectedHookData.String(), actualHookData.String())
	}
	return nil
}
