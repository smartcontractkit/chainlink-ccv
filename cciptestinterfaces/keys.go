package cciptestinterfaces

import "fmt"

// XXXNewVerifierPrivateKey generates a test-only private key for a verifier
// given its index in the test environment.
// This should never be used in production.
func XXXNewVerifierPrivateKey(idx int) string {
	return fmt.Sprintf("dev-private-key%d-12345678901234567890", idx)
}
