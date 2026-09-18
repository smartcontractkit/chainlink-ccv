package chainaccess

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// trackingReader is a SourceReader that also tracks the unfinalized range.
type trackingReader struct{ SourceReader }

func (trackingReader) UnfinalizedRangeChanged(context.Context, *protocol.BlockHeader, *protocol.BlockHeader) (bool, error) {
	return false, nil
}

// plainReader is a SourceReader with no optional capabilities.
type plainReader struct{ SourceReader }

// decorator wraps a SourceReader the way the verifier's observed reader does: by embedding the
// interface, which promotes only the interface's own methods.
type decorator struct{ SourceReader }

func (d decorator) Unwrap() SourceReader { return d.SourceReader }

// cyclicReader unwraps to itself, which must not hang capability resolution.
type cyclicReader struct{ SourceReader }

func (c cyclicReader) Unwrap() SourceReader { return c }

func TestAsUnfinalizedRangeTracker(t *testing.T) {
	tests := []struct {
		name   string
		reader SourceReader
		found  bool
	}{
		{name: "plain reader has no capability", reader: plainReader{}, found: false},
		{name: "tracking reader", reader: trackingReader{}, found: true},
		{name: "tracker behind one decorator", reader: decorator{SourceReader: trackingReader{}}, found: true},
		{
			name:   "tracker behind nested decorators",
			reader: decorator{SourceReader: decorator{SourceReader: trackingReader{}}},
			found:  true,
		},
		{name: "decorator over a plain reader", reader: decorator{SourceReader: plainReader{}}, found: false},
		{name: "decorator over a nil reader", reader: decorator{}, found: false},
		{name: "cyclic unwrap terminates", reader: cyclicReader{}, found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker, ok := AsUnfinalizedRangeTracker(tt.reader)
			require.Equal(t, tt.found, ok)
			if tt.found {
				require.NotNil(t, tracker)
			}
		})
	}
}
