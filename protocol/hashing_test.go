package protocol

import (
	"testing"

	"golang.org/x/crypto/sha3"
)

var data = []byte("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog")

func BenchmarkHashing(b *testing.B) {
	for b.Loop() {
		Keccak256(data)
	}
}

func BenchmarkHashinbBaseline(b *testing.B) {
	for b.Loop() {
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		var out [32]byte
		copy(out[:], h.Sum(nil))
		hasherPool.Put(h)
	}
}
