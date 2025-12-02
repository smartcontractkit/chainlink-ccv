package cctp

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type AttestationService interface {
	// Fetch retrieves the attestation for a given transaction hash and message.
	Fetch(ctx context.Context, txHash protocol.ByteSlice, message protocol.Message) (protocol.ByteSlice, error)
}

type HTTPAttestationService struct {
	api      string
	timeout  time.Duration
	interval time.Duration
	cooldown time.Duration
}

func NewAttestationService(
	config Config,
) AttestationService {
	return &HTTPAttestationService{
		api:      config.AttestationAPI,
		timeout:  config.AttestationAPITimeout,
		interval: config.AttestationAPIInterval,
		cooldown: config.AttestationAPICooldown,
	}
}

func (h HTTPAttestationService) Fetch(
	ctx context.Context,
	txHash protocol.ByteSlice,
	message protocol.Message,
) (protocol.ByteSlice, error) {
	// Call CCTPv2 using sourceChainDomain + txHash
	// Find the attestation with the results set and return
	// 		hookData can be found in attestation response - decodedMessage.decodedMessageBody.hookData
	//      hookData format is the following <4 byte verifier version><32 byte msg ID>
	return txHash, nil
}
