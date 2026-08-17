package services

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadTail covers the bounded tail read used for readiness-failure diagnostics: it must keep
// the END of the stream (where the startup error is) while never buffering more than maxBytes.
func TestReadTail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxBytes int
		want     string
	}{
		{name: "keeps the whole stream when it fits", input: "startup failed", maxBytes: 64, want: "startup failed"},
		{name: "keeps the tail when the stream is longer", input: "0123456789", maxBytes: 4, want: "6789"},
		{name: "handles an exact fit", input: "0123", maxBytes: 4, want: "0123"},
		{name: "handles an empty stream", input: "", maxBytes: 8, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readTail(strings.NewReader(tt.input), tt.maxBytes)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))
		})
	}

	t.Run("keeps the tail across many small reads", func(t *testing.T) {
		// oneByteReader forces the multi-chunk path that the ring logic exists for.
		got, err := readTail(oneBytePerRead(strings.Repeat("ab", 5000)), 6)
		require.NoError(t, err)
		require.Equal(t, "ababab", string(got))
	})

	t.Run("returns what it read before a mid-stream failure", func(t *testing.T) {
		wantErr := errors.New("stream broke")
		got, err := readTail(io.MultiReader(strings.NewReader("early logs"), errReader{wantErr}), 64)
		require.ErrorIs(t, err, wantErr)
		require.Equal(t, "early logs", string(got), "a partial tail is still worth reporting")
	})
}

// oneBytePerRead returns a reader that yields s one byte per Read call.
func oneBytePerRead(s string) io.Reader { return &oneByteReader{s: s} }

type oneByteReader struct {
	s string
	i int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	p[0] = r.s[r.i]
	r.i++
	return 1, nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestContainerLogTailGuards(t *testing.T) {
	t.Run("reports a missing container handle", func(t *testing.T) {
		require.Equal(t, "<no container handle>", ContainerLogTail(t.Context(), nil, 1024))
	})

	t.Run("does not panic on a non-positive size", func(t *testing.T) {
		require.Equal(t, "<no log tail requested>", ContainerLogTail(t.Context(), nil, 0))
	})
}
