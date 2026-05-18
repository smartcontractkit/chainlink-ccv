package chainreg

import (
	"fmt"
	"maps"
	"sync"
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

// Add registers reg for family. If the family is already registered, Add merges
// any fields that were not already set. Existing fields win.
func (r *Registry) Add(family string, reg Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, exists := r.registrations[family]; exists {
		r.registrations[family] = mergeRegistration(existing, reg)
		return nil
	}

	r.registrations[family] = reg
	return nil
}

func mergeRegistration(existing, incoming Registration) Registration {
	if existing.ImplFactory == nil {
		existing.ImplFactory = incoming.ImplFactory
	}
	if existing.CLDFProvider == nil {
		existing.CLDFProvider = incoming.CLDFProvider
	}
	if existing.ChainConfigLoader == nil {
		existing.ChainConfigLoader = incoming.ChainConfigLoader
	}
	if existing.Launcher == nil {
		existing.Launcher = incoming.Launcher
	}
	if existing.VerifierModifier == nil {
		existing.VerifierModifier = incoming.VerifierModifier
	}
	if existing.ExecutorModifier == nil {
		existing.ExecutorModifier = incoming.ExecutorModifier
	}
	if len(incoming.ExtraArgsSerializers) > 0 {
		if existing.ExtraArgsSerializers == nil {
			existing.ExtraArgsSerializers = make(map[uint8]ExtraArgsSerializer, len(incoming.ExtraArgsSerializers))
		}
		for version, serializer := range incoming.ExtraArgsSerializers {
			if _, exists := existing.ExtraArgsSerializers[version]; !exists {
				existing.ExtraArgsSerializers[version] = serializer
			}
		}
	}
	return existing
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

// GetVerifierModifiers returns a map of chain family to verifier modifier from the registry.
func (r *Registry) GetVerifierModifiers() map[string]VerifierModifier {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modifiers := make(map[string]VerifierModifier)
	for family, reg := range r.registrations {
		if reg.VerifierModifier != nil {
			modifiers[family] = reg.VerifierModifier
		}
	}
	return modifiers
}

// GetExtraArgsSerializer returns the registered extra-args serializer for family and version.
func (r *Registry) GetExtraArgsSerializer(family string, version uint8) (ExtraArgsSerializer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.registrations[family]
	if !ok || reg.ExtraArgsSerializers == nil {
		return nil, false
	}
	serializer, ok := reg.ExtraArgsSerializers[version]
	return serializer, ok
}

// GetExecutorModifiers returns a map of chain family to executor modifier from the registry.
func (r *Registry) GetExecutorModifiers() map[string]ExecutorModifier {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modifiers := make(map[string]ExecutorModifier)
	for family, reg := range r.registrations {
		if reg.ExecutorModifier != nil {
			modifiers[family] = reg.ExecutorModifier
		}
	}
	return modifiers
}
