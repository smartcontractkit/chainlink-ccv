package cciptestinterfaces

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// XXXNewVerifierPrivateKey generates a test-only private key for a verifier
// given its index in the test environment.
// This should never be used in production.
//
// Note: if you change this function, you need to update the public keys in the aggregator.toml file
// that is currently being used for tests.
func XXXNewVerifierPrivateKey(committeeName string, nodeIndex int) string {
	preImage := fmt.Sprintf("dev-private-key-%s-%d-12345678901234567890", committeeName, nodeIndex)
	hash := sha256.Sum256([]byte(preImage))
	return hex.EncodeToString(hash[:])
}
