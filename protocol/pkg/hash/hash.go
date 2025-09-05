package hash

import (
	"golang.org/x/crypto/sha3"
)

// Keccak256 calculates keccak256 hash of arbitrary data.
func Keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}
