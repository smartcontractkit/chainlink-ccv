package protocol

import (
	"hash"
	"sync"

	"golang.org/x/crypto/sha3"
)

var hasherPool = sync.Pool{
	New: func() any {
		return sha3.NewLegacyKeccak256()
	},
}

// Keccak256 computes the Keccak256 hash of the input.
func Keccak256(data []byte) [32]byte {
	h, ok := hasherPool.Get().(hash.Hash)
	if !ok {
		// This should never happen, but just in case.
		h = sha3.NewLegacyKeccak256()
	}

	h.Reset()
	h.Write(data) //nolint // keccak256 never returns an error
	var out [32]byte
	copy(out[:], h.Sum(nil))
	hasherPool.Put(h)
	return out
}
