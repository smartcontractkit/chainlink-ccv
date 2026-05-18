package chainreg

import (
	"fmt"
	"maps"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
)

// Registry maps chain family to Registration.
type Registry struct {
	mu            sync.RWMutex
	registrations map[string]Registration
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		registrations: make(map[string]Registration),
	}
}

var (
	singletonRegistry *Registry
	registryOnce      sync.Once
)

// GetRegistry returns the process-wide chain registration registry.
func GetRegistry() *Registry {
	registryOnce.Do(func() {
		singletonRegistry = NewRegistry()
	})
	return singletonRegistry
}

// Register adds a Registration for family on the process-wide registry.
func Register(family string, reg Registration) error {
	return GetRegistry().Add(family, reg)
}

// Add registers reg for family. If the family is already registered, Add is a no-op and returns nil.
func (r *Registry) Add(family string, reg Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.registrations[family]; exists {
		return nil
	}

	r.registrations[family] = reg
	r.applySideEffects(family, reg)
	return nil
}

func (r *Registry) applySideEffects(family string, reg Registration) {
	for version, serializer := range reg.ExtraArgsSerializers {
		cciptestinterfaces.RegisterExtraArgsSerializer(
			cciptestinterfaces.ExtraArgsSerializerEntry{Family: family, Version: version},
			serializer,
		)
	}
	if reg.VerifierModifier != nil {
		committeeverifier.SetModifier(family, reg.VerifierModifier)
	}
	if reg.ExecutorModifier != nil {
		executor.SetModifier(family, reg.ExecutorModifier)
	}
}

// Get returns the Registration for family.
func (r *Registry) Get(family string) (Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.registrations[family]
	if !ok {
		return Registration{}, fmt.Errorf("chain registration for family %s not found", family)
	}
	return reg, nil
}

// GetAll returns a snapshot of all registrations keyed by family.
func (r *Registry) GetAll() map[string]Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]Registration, len(r.registrations))
	maps.Copy(result, r.registrations)
	return result
}

// GetAllImplFactories returns a snapshot of ImplFactory values for registered families.
func (r *Registry) GetAllImplFactories() map[string]ImplFactory {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]ImplFactory)
	for family, reg := range r.registrations {
		if reg.ImplFactory != nil {
			result[family] = reg.ImplFactory
		}
	}
	return result
}
