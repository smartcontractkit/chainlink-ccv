package common

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	vHash = protocol.Keccak256([]byte("CCIP1.7_MessageDiscovery_Version"))
	// MessageDiscoveryVersion is the version used by the committee verifier to sign messages
	// that only need to be discovered, and not verified onchain.
	// 0x3c4605eb in hex.
	MessageDiscoveryVersion = vHash[:4]
)

const (
	// The number of bytes used to represent the verifier version.
	VerifierVersionLength = 4
)

// NewSignableHash creates a new hash from the given message ID and verifier blob data.
// This hash is ultimately signed by each committee verifier.
func NewSignableHash(messageID protocol.Bytes32, verifierBlobData []byte) ([32]byte, error) {
	blobLen := len(verifierBlobData)
	if blobLen == 0 {
		return [32]byte{}, fmt.Errorf("verifier blob data not found for message %s", messageID.String())
	}
	if blobLen < VerifierVersionLength {
		return [32]byte{}, fmt.Errorf("verifier blob data too short for message %s (expected at least %d bytes, got %d)", messageID.String(), VerifierVersionLength, blobLen)
	}
	var preImage []byte
	preImage = append(preImage, verifierBlobData[:VerifierVersionLength]...)
	preImage = append(preImage, messageID[:]...)
	return protocol.Keccak256(preImage), nil
}
