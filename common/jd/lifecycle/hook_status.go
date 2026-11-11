package lifecycle

import "sync"

// HookStatus is a health reporter for the on-connect hook. It is degraded while the last attempt
// failed and fine otherwise, including before the first attempt.
type HookStatus struct {
	name string

	mu  sync.Mutex
	err error
}

// NewHookStatus returns a HookStatus reported on /health under name.
func NewHookStatus(name string) *HookStatus {
	return &HookStatus{name: name}
}

func (s *HookStatus) set(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Name implements protocol.HealthReporter.
func (s *HookStatus) Name() string { return s.name }

// Ready implements protocol.HealthReporter. A failing hook degrades the service; it never stops it.
func (s *HookStatus) Ready() error { return nil }

// Degraded implements health.DegradedReporter: the last attempt's error, nil once one succeeds.
func (s *HookStatus) Degraded() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// HealthReport implements protocol.HealthReporter.
func (s *HookStatus) HealthReport() map[string]error {
	return map[string]error{s.name: s.Degraded()}
}
