package auth

import "sync"

// HMACFailureTracker tracks consecutive HMAC signature verification failures per client
// and invokes an optional callback when a client exceeds the threshold.
type HMACFailureTracker struct {
	mu        sync.Mutex
	counts    map[string]int
	threshold int
	onDisable func(clientID string)
}

// NewHMACFailureTracker returns a tracker that records failures and calls onDisable(clientID)
// when a client's consecutive failures reach threshold. If threshold is 0 or onDisable is nil,
// the tracker is effectively disabled.
func NewHMACFailureTracker(threshold int, onDisable func(clientID string)) *HMACFailureTracker {
	if threshold <= 0 || onDisable == nil {
		return &HMACFailureTracker{counts: make(map[string]int)}
	}
	return &HMACFailureTracker{
		counts:    make(map[string]int),
		threshold: threshold,
		onDisable: onDisable,
	}
}

// RecordHMACVerificationFailure records a signature failure for the client; returns true if the client was disabled.
func (t *HMACFailureTracker) RecordHMACVerificationFailure(clientID string) (clientWasDisabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.threshold <= 0 || t.onDisable == nil {
		return false
	}
	t.counts[clientID]++
	if t.counts[clientID] < t.threshold {
		return false
	}
	t.onDisable(clientID)
	return true
}

// RecordHMACVerificationSuccess resets the consecutive failure count for the client.
func (t *HMACFailureTracker) RecordHMACVerificationSuccess(clientID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.counts, clientID)
}

// ClientProviderWithHMACRecorder wraps a ClientProvider and an HMACFailureRecorder so that
// a single value can be passed to the HMAC middleware for both lookup and recording.
type ClientProviderWithHMACRecorder struct {
	ClientProvider
	Recorder HMACFailureRecorder
}

// RecordHMACVerificationFailure delegates to the wrapped recorder.
func (c *ClientProviderWithHMACRecorder) RecordHMACVerificationFailure(clientID string) (clientWasDisabled bool) {
	return c.Recorder.RecordHMACVerificationFailure(clientID)
}

// RecordHMACVerificationSuccess delegates to the wrapped recorder.
func (c *ClientProviderWithHMACRecorder) RecordHMACVerificationSuccess(clientID string) {
	c.Recorder.RecordHMACVerificationSuccess(clientID)
}
