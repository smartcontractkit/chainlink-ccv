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
		panic("cannot get hasher")
	}

	h.Reset()
	h.Write(data) // nolint:revive // keccak256 never returns an error
	var out [32]byte
	copy(out[:], h.Sum(nil))
	h.Reset()
	hasherPool.Put(h)
	return out
}
