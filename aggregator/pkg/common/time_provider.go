package common

import "time"

type TimeProvider interface {
	// Now returns the current time.
	Now() time.Time
}

type realTimeProvider struct{}

func (r *realTimeProvider) Now() time.Time {
	return time.Now()
}

func NewRealTimeProvider() TimeProvider {
	return &realTimeProvider{}
}

type MockTimeProvider struct {
	currentTime time.Time
}

func (m *MockTimeProvider) Now() time.Time {
	return m.currentTime
}

func (m *MockTimeProvider) SetTime(t time.Time) {
	m.currentTime = t
}

func (m *MockTimeProvider) AdvanceTime(d time.Duration) {
	m.currentTime = m.currentTime.Add(d)
}

func NewMockTimeProvider(initialTime time.Time) *MockTimeProvider {
	return &MockTimeProvider{
		currentTime: initialTime,
	}
}
