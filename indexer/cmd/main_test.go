package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ccvhealth "github.com/smartcontractkit/chainlink-ccv/common/health"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// A skipped verifier must be recorded in the startup skips reporter so
// /health/ready returns 503 and pages instead of silently missing the verifier.
func TestCreateAllVerifierReaders_RecordsSkips(t *testing.T) {
	cfg := &config.Config{
		Verifiers: []config.VerifierConfig{
			{Name: "good", Type: config.ReaderTypeRest, RestReaderConfig: config.RestReaderConfig{BaseURL: "http://localhost:8080/v1"}},
			{Name: "bad", Type: config.ReaderType("bogus")},
		},
	}
	startupSkips := ccvhealth.NewStartupSkips("indexer.StartupSkips")

	lggr := logger.Test(t)
	err := createAllVerifierReaders(t.Context(), lggr, registry.NewVerifierRegistry(), cfg, monitoring.NewNoopIndexerMonitoring(), startupSkips)

	require.NoError(t, err, "one usable verifier must be enough to start")
	require.ErrorContains(t, startupSkips.Ready(), "1 component(s) skipped at startup")
	require.ErrorContains(t, startupSkips.Ready(), "VerifierReader[bad]: unknown verifier type")
	assert.NotContains(t, startupSkips.Ready().Error(), "VerifierReader[good]")
}

func TestCreateAllVerifierReaders_FailsWhenNoVerifierUsable(t *testing.T) {
	cfg := &config.Config{
		Verifiers: []config.VerifierConfig{
			{Name: "bad", Type: config.ReaderType("bogus")},
		},
	}
	startupSkips := ccvhealth.NewStartupSkips("indexer.StartupSkips")

	err := createAllVerifierReaders(t.Context(), logger.Test(t), registry.NewVerifierRegistry(), cfg, monitoring.NewNoopIndexerMonitoring(), startupSkips)

	require.ErrorContains(t, err, "failed to create readers for any of the 1 configured verifiers")
}
