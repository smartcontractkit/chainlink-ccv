package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMACFailureTracker_DisablesAfterNConsecutiveFailures(t *testing.T) {
	var disabledID string
	onDisable := func(clientID string) { disabledID = clientID }
	tracker := NewHMACFailureTracker(2, onDisable)

	disabled := tracker.RecordHMACVerificationFailure("c1")
	assert.False(t, disabled)
	assert.Empty(t, disabledID)

	disabled = tracker.RecordHMACVerificationFailure("c1")
	assert.True(t, disabled)
	assert.Equal(t, "c1", disabledID)
}

func TestHMACFailureTracker_SuccessResetsCount(t *testing.T) {
	callCount := 0
	onDisable := func(string) { callCount++ }
	tracker := NewHMACFailureTracker(2, onDisable)

	tracker.RecordHMACVerificationFailure("c1")
	tracker.RecordHMACVerificationSuccess("c1")
	disabled := tracker.RecordHMACVerificationFailure("c1")
	require.False(t, disabled, "count was reset so one failure should not trigger disable")
	assert.Equal(t, 0, callCount)
}

func TestHMACFailureTracker_ZeroThresholdDoesNotDisable(t *testing.T) {
	onDisable := func(string) { t.Error("onDisable should not be called") }
	tracker := NewHMACFailureTracker(0, onDisable)

	disabled := tracker.RecordHMACVerificationFailure("c1")
	assert.False(t, disabled)
}

func TestHMACFailureTracker_NilOnDisableDoesNotPanic(t *testing.T) {
	tracker := NewHMACFailureTracker(1, nil)

	disabled := tracker.RecordHMACVerificationFailure("c1")
	assert.False(t, disabled)
}

func TestHMACFailureTracker_RecordSuccessNoOpWhenDisabled(t *testing.T) {
	tracker := NewHMACFailureTracker(0, nil)
	tracker.RecordHMACVerificationSuccess("c1")
}
