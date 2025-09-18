package pkg

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// MessageSigner defines the interface for signing messages using the new chain-agnostic format.
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature and verifier blob
	SignMessage(ctx context.Context, verificationTask types.VerificationTask, sourceVerifierAddress protocol.UnknownAddress) ([]byte, []byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() protocol.UnknownAddress
}
