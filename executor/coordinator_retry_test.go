package executor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCoordinator_dataNotReadyBackoff(t *testing.T) {
	t.Parallel()

	ec := &Coordinator{dataNotReadyRetryInterval: time.Second}
	stagger := 30 * time.Second

	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{name: "first attempt", attempt: 1, want: time.Second},
		{name: "second attempt", attempt: 2, want: 2 * time.Second},
		{name: "third attempt", attempt: 3, want: 4 * time.Second},
		{name: "capped at stagger", attempt: 10, want: stagger},
		{name: "zero attempt normalized", attempt: 0, want: time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ec.dataNotReadyBackoff(tc.attempt, stagger)
			require.Equal(t, tc.want, got)
		})
	}
}
