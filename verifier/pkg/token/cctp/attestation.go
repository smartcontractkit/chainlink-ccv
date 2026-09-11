package cctp

import (
	"context"
	"fmt"

	"github.com/mr-tron/base58"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AttestationService interface {
	// Fetch retrieves the attestation for a given transaction hash and message.
	Fetch(ctx context.Context, txHash protocol.ByteSlice, message protocol.Message) (Attestation, error)
}

// Attestation represents a CCTP attestation along with related data
// allowing creating proper payload for the verifier on the destination chain.
// Please see ToVerifierFormat for more details on the format.
type Attestation struct {
	verifierVersion    protocol.ByteSlice
	attestation        string
	encodedCCTPMessage string
	status             AttestationStatus
}

func NewAttestation(verifierVersion protocol.ByteSlice, msg Message) Attestation {
	return Attestation{
		verifierVersion:    verifierVersion,
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

	output := make(protocol.ByteSlice, 0, len(a.verifierVersion)+len(encodedCCTPMessage)+len(attestation))
	output = append(output, a.verifierVersion...)
	output = append(output, encodedCCTPMessage...)
	output = append(output, attestation...)
	return output, nil
}

func (a *Attestation) IsReady() bool {
	return a.status == attestationStatusSuccess
}

type HTTPAttestationService struct {
	lggr              logger.Logger
	client            HTTPClient
	verifierVersion   protocol.ByteSlice
	verifierAddresses map[protocol.ChainSelector]protocol.UnknownAddress
}

func NewAttestationService(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	config CCTPConfig,
) (AttestationService, error) {
	client, err := NewHTTPClient(lggr, monitoring, config)
	if err != nil {
		return nil, err
	}

	return &HTTPAttestationService{
		lggr:              lggr,
		client:            client,
		verifierVersion:   config.VerifierVersion,
		verifierAddresses: config.ParsedVerifiers,
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
	sourceDomain, ok := Domains[uint64(message.SourceChainSelector)]
	if !ok {
		return Attestation{}, fmt.Errorf("unsupported source chain selector: %d", message.SourceChainSelector)
	}

	encodedTxHash, err := encodeTxHash(message.SourceChainSelector, txHash)
	if err != nil {
		return Attestation{}, err
	}

	response, err := h.client.GetMessages(ctx, sourceDomain, encodedTxHash)
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
		err := cctpMatchesMessage(h.verifierVersion, h.verifierAddresses, msg, message)
		if err != nil {
			h.lggr.Debugw(
				"skipping CCTP message as it doesn't match CCIP message",
				"message", msg,
				"reason", err,
			)
			continue
		}
		return NewAttestation(h.verifierVersion, msg), nil
	}
	return Attestation{}, fmt.Errorf("no matching message found in response")
}

func cctpMatchesMessage(
	verifierVersion protocol.ByteSlice,
	verifierAddresses map[protocol.ChainSelector]protocol.UnknownAddress,
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

	verifierAddress, ok := verifierAddresses[ccipMessage.SourceChainSelector]
	if !ok {
		return fmt.Errorf("no CCV address configured for source chain selector: %s", ccipMessage.SourceChainSelector)
	}

	senderAddress, err := decodeAddress(ccipMessage.SourceChainSelector, cctpMessage.DecodedMessage.DecodedMessageBody.MessageSender)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	if !verifierAddress.Equal(senderAddress) {
		return fmt.Errorf("sender address mismatch: expected %s, got %s", verifierAddress.String(), senderAddress.String())
	}

	actualHookData, err := protocol.NewByteSliceFromHex(cctpMessage.DecodedMessage.DecodedMessageBody.HookData)
	if err != nil {
		return fmt.Errorf("invalid hook data: %w", err)
	}

	// <4 byte verifier version><32 byte msg ID>
	expectedHookData := make(protocol.ByteSlice, 0, len(verifierVersion)+len(messageID))
	expectedHookData = append(expectedHookData, verifierVersion...)
	expectedHookData = append(expectedHookData, messageID[:]...)
	if actualHookData.String() != expectedHookData.String() {
		return fmt.Errorf("hook data mismatch: expected %s, got %s", expectedHookData.String(), actualHookData.String())
	}
	return nil
}

// TODO: inject a per-family address codec into HTTPAttestationService instead of
// branching on the chain family here. Circle encodes each address in the native format of the
// chain it belongs to, so both the request and the response need the source chain's codec. The
// switch below covers the families CCTP supports today; every new non-EVM family needs another
// branch until the codec is injected.

// encodeTxHash renders a transaction hash in the format Circle's API expects for the source chain.
// Solana signatures are base58; every other family uses 0x-prefixed hex.
func encodeTxHash(selector protocol.ChainSelector, txHash protocol.ByteSlice) (string, error) {
	family, err := chainsel.GetSelectorFamily(uint64(selector))
	if err != nil {
		return "", fmt.Errorf("resolve chain family for selector %d: %w", selector, err)
	}
	if family == chainsel.FamilySolana {
		return base58.Encode(txHash), nil
	}
	return txHash.String(), nil
}

// decodeAddress parses an address that Circle returned for the given source chain. Solana
// addresses come back base58, every other family as 0x-prefixed hex.
func decodeAddress(selector protocol.ChainSelector, address string) (protocol.UnknownAddress, error) {
	family, err := chainsel.GetSelectorFamily(uint64(selector))
	if err != nil {
		return nil, fmt.Errorf("resolve chain family for selector %d: %w", selector, err)
	}
	if family == chainsel.FamilySolana {
		decoded, derr := base58.Decode(address)
		if derr != nil {
			return nil, fmt.Errorf("invalid base58 address %q: %w", address, derr)
		}
		return protocol.UnknownAddress(decoded), nil
	}
	return protocol.NewUnknownAddressFromHex(address)
}
