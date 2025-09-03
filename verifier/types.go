package verifier

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
)

// MessageSigner defines the interface for signing messages using the new chain-agnostic format
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature and verifier blob
	SignMessage(ctx context.Context, verificationTask types.VerificationTask, sourceVerifierAddress common.UnknownAddress) ([]byte, []byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() common.UnknownAddress
}
