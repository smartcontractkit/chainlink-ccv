package readers

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadLimitedBody(t *testing.T) {
	tests := []struct {
		name       string
		body       io.Reader
		maxBytes   int
		wantLen    int
		wantErr    error
		wantAnyErr bool
	}{
		{
			name:     "returns body within limit",
			body:     bytes.NewReader([]byte("hello world")),
			maxBytes: 1024,
			wantLen:  11,
		},
		{
			name:     "returns body exactly at limit",
			body:     bytes.NewReader(make([]byte, 100)),
			maxBytes: 100,
			wantLen:  100,
		},
		{
			name:     "rejects body exceeding limit",
			body:     bytes.NewReader(make([]byte, 101)),
			maxBytes: 100,
			wantErr:  ErrResponseTooLarge,
		},
		{
			name:     "returns empty body within limit",
			body:     bytes.NewReader(nil),
			maxBytes: 100,
			wantLen:  0,
		},
		{
			name:       "rejects zero maxBytes",
			body:       bytes.NewReader(nil),
			maxBytes:   0,
			wantAnyErr: true,
		},
		{
			name:       "rejects negative maxBytes",
			body:       bytes.NewReader(nil),
			maxBytes:   -1,
			wantAnyErr: true,
		},
		{
			name:       "propagates reader error",
			body:       io.NopCloser(&failingReader{}),
			maxBytes:   1024,
			wantAnyErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := readLimitedBody(tt.body, tt.maxBytes)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			if tt.wantAnyErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, b, tt.wantLen)
		})
	}
}

type failingReader struct{}

func (f *failingReader) Read(_ []byte) (int, error) {
	return 0, assert.AnError
}
