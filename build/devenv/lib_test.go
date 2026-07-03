package ccv

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLibFromCCV(cfg *Cfg) *libFromCCV {
	return &libFromCCV{
		envOutFile: "test.toml",
		cfg:        cfg,
		l:          zerolog.Nop(),
	}
}

// TestLib_OffchainGetters covers the absence contract for both backends: the plural
// getters return an empty result with a nil error when nothing is configured, the
// singular getters return an error, and a real construction failure surfaces as an
// error from the plural getter too.
func TestLib_OffchainGetters(t *testing.T) {
	ccvUnconfigured := newTestLibFromCCV(&Cfg{})
	ccvBadAggregatorCert := newTestLibFromCCV(&Cfg{
		AggregatorEndpoints:   map[string]string{"default": "127.0.0.1:1"},
		AggregatorCACertFiles: map[string]string{"default": "/nonexistent/ca.pem"},
	})
	cldf := &libFromCLDF{l: zerolog.Nop()}

	tests := []struct {
		name    string
		call    func() (any, error)
		wantErr bool // false: expect an empty result with a nil error
	}{
		{"ccv unconfigured: AllAggregators", func() (any, error) { return ccvUnconfigured.AllAggregators() }, false},
		{"ccv unconfigured: AllIndexers", func() (any, error) { return ccvUnconfigured.AllIndexers() }, false},
		{"ccv unconfigured: Indexer", func() (any, error) { return ccvUnconfigured.Indexer() }, true},
		{"ccv unconfigured: IndexerMonitor", func() (any, error) { return ccvUnconfigured.IndexerMonitor() }, true},
		{"ccv bad aggregator cert: AllAggregators", func() (any, error) { return ccvBadAggregatorCert.AllAggregators() }, true},
		{"cldf: AllAggregators", func() (any, error) { return cldf.AllAggregators() }, false},
		{"cldf: AllIndexers", func() (any, error) { return cldf.AllIndexers() }, false},
		{"cldf: Indexer", func() (any, error) { return cldf.Indexer() }, true},
		{"cldf: IndexerMonitor", func() (any, error) { return cldf.IndexerMonitor() }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.call()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}
