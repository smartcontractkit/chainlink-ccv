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
	attestation        string
	encodedCCTPMessage string
	status             AttestationStatus
}

func NewAttestation(ccvVerifierVersion protocol.ByteSlice, msg Message) Attestation {
	return Attestation{
		ccvVerifierVersion: ccvVerifierVersion,
		attestation:        msg.Attestation,
		encodedCCTPMessage: msg.Message,
		status:             msg.Status,
	}
}

// ToVerifierFormat converts the message into format expected by verifier on the dest
// <4 byte verifier version><encoded CCTP message><attestation>.
func (a *Attestation) ToVerifierFormat() (protocol.ByteSlice, error) {
	if !a.IsReady() {
		return nil, fmt.Errorf("attestation is not ready, status: %s", a.status)
	}
	attestation, err := protocol.NewByteSliceFromHex(a.attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation hex: %w", err)
	}
	encodedCCTPMessage, err := protocol.NewByteSliceFromHex(a.encodedCCTPMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CCTP message: %w", err)
	}

	var output protocol.ByteSlice
	output = append(output, a.ccvVerifierVersion...)
	output = append(output, encodedCCTPMessage...)
	output = append(output, attestation...)
	return output, nil
}

func (a *Attestation) IsReady() bool {
	return a.status == attestationStatusSuccess
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
		ccvVerifierVersion: CCVVerifierVersion,
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
		return NewAttestation(h.ccvVerifierVersion, msg), nil
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

	senderAddress, err := protocol.NewUnknownAddressFromHex(cctpMessage.DecodedMessage.DecodedMessageBody.MessageSender)
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
