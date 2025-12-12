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
		ok := h.matchesMessage(msg, message)
		if !ok {
			h.lggr.Debugw("skipping CCTP message as it doesn't match CCIP message", "message", msg)
			continue
		}
		if msg.IsAttestationComplete() {
			return NewAttestation(h.ccvVerifierVersion, msg)
		}
		return Attestation{}, fmt.Errorf("attestation is not ready")
	}
	return Attestation{}, fmt.Errorf("no matching message found in response")
}

func (h *HTTPAttestationService) matchesMessage(msg Message, message protocol.Message) bool {
	messageID, err := message.MessageID()
	if err != nil {
		return false
	}

	lggr := logger.With(h.lggr, "cctpMessage", message, "messageID", messageID)

	if !msg.IsV2() {
		lggr.Debugw("CCTP Attestation: Skipping message due to unsupported CCTP version")
		return false
	}

	ccvAddress, ok := h.ccvAddresses[message.SourceChainSelector]
	if !ok {
		lggr.Debugw("CCTP Attestation: No CCV address configured for source chain selector",
			"sourceChainSelector", message.SourceChainSelector)
		return false
	}

	senderAddress := protocol.UnknownAddress(msg.DecodedMessage.Sender)
	if !ccvAddress.Equal(senderAddress) {
		lggr.Debugw("CCTP Attestation: Skipping message due to sender address mismatch",
			"expectedSender", ccvAddress.String(),
			"actualSender", senderAddress.String(),
		)
		return false
	}

	actualHookData, err := protocol.NewByteSliceFromHex(msg.DecodedMessage.DecodedMessageBody.HookData)
	if err != nil {
		lggr.Debugw("CCTP Attestation: Skipping message due to invalid hook data",
			"hookData", msg.DecodedMessage.DecodedMessageBody.HookData,
			"error", err,
		)
		return false
	}

	// <4 byte verifier version><32 byte msg ID>
	var expectedHookData protocol.ByteSlice
	expectedHookData = append(expectedHookData, h.ccvVerifierVersion...)
	expectedHookData = append(expectedHookData, messageID[:]...)
	if actualHookData.String() != expectedHookData.String() {
		lggr.Debugw("CCTP Attestation: Skipping message due to hook data mismatch",
			"expectedHookData", expectedHookData.String(),
			"actualHookData", actualHookData.String(),
		)
		return false
	}
	return true
}
