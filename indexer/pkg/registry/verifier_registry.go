package registry

import (
	"errors"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerifierRegistry is a thread-safe registry that maps verifier addresses
// to their corresponding VerifierReader instances.
//
// A single on-chain verifier address may have multiple readers (e.g. backed
// by redundant aggregators in an HA setup). All readers registered for the
// same address are returned by GetVerifiers; GetVerifier returns the first.
//
// The zero value is not ready for use. Use NewVerifierRegistry to create
// a new instance.
//
// VerifierRegistry is safe for concurrent use by multiple goroutines.
type VerifierRegistry struct {
	verifiers  map[string][]*readers.VerifierReader
	addrToName map[string]string
	mu         sync.RWMutex
}

// NewVerifierRegistry creates and returns a new VerifierRegistry instance.
func NewVerifierRegistry() *VerifierRegistry {
	return &VerifierRegistry{
		verifiers:  make(map[string][]*readers.VerifierReader),
		addrToName: make(map[string]string),
	}
}

// AddVerifier registers a verifier reader for the given on-chain address.
// Multiple readers may be registered for the same address to support
// redundant aggregators (HA). The first registered name is kept.
//
// AddVerifier is safe for concurrent use.
func (v *VerifierRegistry) AddVerifier(address protocol.UnknownAddress, name string, verifier *readers.VerifierReader) error {
	if verifier == nil {
		return errors.New("verifier cannot be nil")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	key := address.String()
	v.verifiers[key] = append(v.verifiers[key], verifier)

	// Keep the first name registered for this address.
	if _, ok := v.addrToName[key]; !ok {
		v.addrToName[key] = name
	}

	return nil
}

// RemoveVerifier removes all verifier readers associated with the given address
// from the registry. If no verifier exists for the address, RemoveVerifier
// returns an error.
//
// RemoveVerifier is safe for concurrent use.
func (v *VerifierRegistry) RemoveVerifier(address protocol.UnknownAddress) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := address.String()
	if _, ok := v.verifiers[key]; !ok {
		return errors.New("verifier does not exist")
	}

	if _, ok := v.addrToName[key]; !ok {
		return errors.New("name mapping does not exist for verifier")
	}

	delete(v.verifiers, key)
	delete(v.addrToName, key)
	return nil
}

// GetVerifier returns the first verifier reader associated with the given address.
// If no verifier exists for the address, GetVerifier returns nil.
//
// GetVerifier is safe for concurrent use.
func (v *VerifierRegistry) GetVerifier(address protocol.UnknownAddress) *readers.VerifierReader {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if readers := v.verifiers[address.String()]; len(readers) > 0 {
		return readers[0]
	}
	return nil
}

// GetVerifiers returns all verifier readers associated with the given address.
// In an HA setup multiple readers may be backed by different aggregators.
// Returns nil if no verifier exists for the address.
//
// GetVerifiers is safe for concurrent use.
func (v *VerifierRegistry) GetVerifiers(address protocol.UnknownAddress) []*readers.VerifierReader {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.verifiers[address.String()]
}

// GetVerifierNameFromAddress returns the name associated with the verifier.
// This is commonly used in returning metadata for the verifier.
//
// GetVerifierNameFromAddress is safe for concurrent use.
func (v *VerifierRegistry) GetVerifierNameFromAddress(address protocol.UnknownAddress) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.addrToName[address.String()]
}
