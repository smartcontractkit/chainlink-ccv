package registry

import (
	"errors"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerifierRegistry is a thread-safe registry that maps verifier addresses
// to their corresponding VerifierReader instances.
//
// The zero value is not ready for use. Use NewVerifierRegistry to create
// a new instance.
//
// VerifierRegistry is safe for concurrent use by multiple goroutines.
type VerifierRegistry struct {
	verifiers map[string]*common.VerifierReader
	mu        sync.RWMutex
}

// NewVerifierRegistry creates and returns a new VerifierRegistry instance.
func NewVerifierRegistry() *VerifierRegistry {
	return &VerifierRegistry{
		verifiers: make(map[string]*common.VerifierReader),
	}
}

// AddVerifier adds a verifier reader to the registry associated with the given address.
// If a verifier with the same address already exists, AddVerifier returns an error.
//
// AddVerifier is safe for concurrent use.
func (v *VerifierRegistry) AddVerifier(address protocol.UnknownAddress, verifier *common.VerifierReader) error {
	if verifier == nil {
		return errors.New("verifier cannot be nil")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	key := address.String()
	if _, ok := v.verifiers[key]; ok {
		return errors.New("verifier already exists")
	}

	v.verifiers[key] = verifier

	return nil
}

// RemoveVerifier removes the verifier reader associated with the given address
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

	delete(v.verifiers, key)
	return nil
}

// GetVerifier returns the verifier reader associated with the given address.
// If no verifier exists for the address, GetVerifier returns nil.
//
// GetVerifier is safe for concurrent use.
func (v *VerifierRegistry) GetVerifier(address protocol.UnknownAddress) *common.VerifierReader {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.verifiers[address.String()]
}
