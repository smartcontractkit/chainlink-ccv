package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// XXXNewVerifierPrivateKey generates a test-only private key for a verifier
// given its committee name and node index.
// This should never be used in production.
func XXXNewVerifierPrivateKey(committeeName string, nodeIndex int) string {
	preImage := fmt.Sprintf("dev-private-key-%s-%d-12345678901234567890", committeeName, nodeIndex)
	hash := sha256.Sum256([]byte(preImage))
	return hex.EncodeToString(hash[:])
}
