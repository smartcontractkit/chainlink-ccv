package protocol

import (
	"crypto/rand"
)

// RandomAddress generates a random address for testing.
func RandomAddress() (UnknownAddress, error) {
	addr := make([]byte, 20)
	if _, err := rand.Read(addr); err != nil {
		return nil, err
	}
	return addr, nil
}
