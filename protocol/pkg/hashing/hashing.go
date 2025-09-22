package hashing

import "github.com/ethereum/go-ethereum/crypto"

// Keccak256 computes the Keccak256 hash of the input.
func Keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}
