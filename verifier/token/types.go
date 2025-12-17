package token

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type Attestation interface {
	// IsReady checks if the attestation is ready to be submitted to the dest verifier
	IsReady() bool
	// ToVerifierFormat converts the attestation into protocol.ByteSlice expected
	// by the verifier on the destination chain. It checks if attestation is ready
	ToVerifierFormat() (protocol.ByteSlice, error)
}
