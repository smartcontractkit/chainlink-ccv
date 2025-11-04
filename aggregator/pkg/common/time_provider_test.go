package common

import (
	"testing"
	"time"
)

func TestNewRealTimeProvider_NowReturnsCurrentTime(t *testing.T) {
	tp := NewRealTimeProvider()
	before := time.Now().Add(-1 * time.Second)
	now := tp.Now()
	after := time.Now().Add(1 * time.Second)

	if now.Before(before) || now.After(after) {
		t.Fatalf("expected Now() to be close to current time, got %v", now)
	}
}

func TestMockTimeProvider_SetAndAdvance(t *testing.T) {
	initial := time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC)
	tp := NewMockTimeProvider(initial)

	if got := tp.Now(); !got.Equal(initial) {
		t.Fatalf("expected initial time %v, got %v", initial, got)
	}

	// SetTime
	next := initial.Add(5 * time.Minute)
	tp.SetTime(next)
	if got := tp.Now(); !got.Equal(next) {
		t.Fatalf("expected set time %v, got %v", next, got)
	}

	// AdvanceTime
	tp.AdvanceTime(30 * time.Second)
	want := next.Add(30 * time.Second)
	if got := tp.Now(); !got.Equal(want) {
		t.Fatalf("expected advanced time %v, got %v", want, got)
	}
}
