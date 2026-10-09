package health

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// StartupSkips records components skipped at startup (a misconfigured verifier,
// reader, or discovery source). The service keeps running and reports Degraded,
// naming each skipped component. The factory fails startup when none is usable.
type StartupSkips struct {
	name  string
	mu    sync.RWMutex
	skips map[string]error
}

var (
	_ protocol.HealthReporter = (*StartupSkips)(nil)
	_ DegradedReporter        = (*StartupSkips)(nil)
)

// NewStartupSkips creates a skip recorder; name identifies the service in /health.
func NewStartupSkips(name string) *StartupSkips {
	return &StartupSkips{name: name, skips: make(map[string]error)}
}

// Skip records that a component failed to start and was skipped.
func (s *StartupSkips) Skip(component string, err error) {
	if err == nil {
		err = errors.New("skipped at startup")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.skips[component] = err
}

func (s *StartupSkips) Name() string { return s.name }

// Ready is always nil. A skip degrades the service; the factory rejects a service with nothing usable.
func (s *StartupSkips) Ready() error {
	return nil
}

// Degraded is non-nil while any component is skipped. A skip does not self-heal,
// so it stays until the config is fixed and the process restarts.
func (s *StartupSkips) Degraded() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.skipErrLocked()
}

func (s *StartupSkips) skipErrLocked() error {
	if len(s.skips) == 0 {
		return nil
	}
	errs := make([]error, 0, len(s.skips))
	for _, component := range slices.Sorted(maps.Keys(s.skips)) {
		errs = append(errs, fmt.Errorf("%s: %w", component, s.skips[component]))
	}
	return fmt.Errorf("%d component(s) skipped at startup: %w", len(errs), errors.Join(errs...))
}

func (s *StartupSkips) HealthReport() map[string]error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report := make(map[string]error, len(s.skips)+1)
	report[s.name] = s.skipErrLocked()
	for component, err := range s.skips {
		report[fmt.Sprintf("%s[%s]", s.name, component)] = err
	}
	return report
}
