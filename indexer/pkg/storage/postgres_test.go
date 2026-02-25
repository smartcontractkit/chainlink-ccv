package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	indexermonitoring "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

func TestNewPostgresStorage_Errors(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	noopMon := indexermonitoring.NewNoopIndexerMonitoring()

	tests := []struct {
		name          string
		lggr          logger.Logger
		monitoring    common.IndexerMonitoring
		uri           string
		driverName    string
		wantErrSubstr string
	}{
		{
			name:          "nil logger",
			lggr:          nil,
			monitoring:    noopMon,
			uri:           "postgresql://localhost:5432/db?sslmode=disable",
			driverName:    "postgres",
			wantErrSubstr: "logger is required",
		},
		{
			name:          "nil monitoring",
			lggr:          lggr,
			monitoring:    nil,
			uri:           "postgresql://localhost:5432/db?sslmode=disable",
			driverName:    "postgres",
			wantErrSubstr: "monitoring is required",
		},
		{
			name:          "empty uri",
			lggr:          lggr,
			monitoring:    noopMon,
			uri:           "",
			driverName:    "postgres",
			wantErrSubstr: "database URI is required",
		},
		{
			name:          "empty driver name",
			lggr:          lggr,
			monitoring:    noopMon,
			uri:           "postgresql://localhost:5432/db?sslmode=disable",
			driverName:    "",
			wantErrSubstr: "database driver name is required",
		},
		{
			name:          "invalid driver",
			lggr:          lggr,
			monitoring:    noopMon,
			uri:           "monsterjam://localhost:5432/db?sslmode=disable",
			driverName:    "el torro loco",
			wantErrSubstr: "failed to open database connection",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPostgresStorage(context.Background(), tc.lggr, tc.monitoring, tc.uri, tc.driverName, pg.DBConfig{})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErrSubstr)
		})
	}
}
