package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newStartedMockSource returns a MockMessageDiscovery that expects Start once and Close once.
func newStartedMockSource(t *testing.T) *mocks.MockMessageDiscovery {
	t.Helper()
	src := mocks.NewMockMessageDiscovery(t)
	src.EXPECT().Start(mock.Anything).Return().Once()
	src.EXPECT().Close().Return(nil).Once()
	return src
}

func TestMultiSourceMessageDiscovery_StartsAllSources(t *testing.T) {
	sourceA := newStartedMockSource(t)
	sourceB := newStartedMockSource(t)
	sourceC := newStartedMockSource(t)

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB, sourceC},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	multi.Start(ctx)

	for _, src := range []*mocks.MockMessageDiscovery{sourceA, sourceB, sourceC} {
		src.AssertCalled(t, "Start", ctx)
	}
}

func TestMultiSourceMessageDiscovery_SingleSource(t *testing.T) {
	single := newStartedMockSource(t)

	multi, err := NewMultiSourceMessageDiscovery(logger.Test(t), []common.MessageDiscovery{single})
	require.NoError(t, err)

	multi.Start(context.Background())
	require.NoError(t, multi.Close())
}

func TestMultiSourceMessageDiscovery_CloseStopsAll(t *testing.T) {
	sourceA := newStartedMockSource(t)
	sourceB := newStartedMockSource(t)

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)

	multi.Start(context.Background())

	done := make(chan struct{})
	go func() {
		assert.NoError(t, multi.Close())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}
	sourceA.AssertCalled(t, "Close")
	sourceB.AssertCalled(t, "Close")
}

func TestMultiSourceMessageDiscovery_CloseContinuesAfterSourceError(t *testing.T) {
	failing := mocks.NewMockMessageDiscovery(t)
	failing.EXPECT().Start(mock.Anything).Return().Once()
	failing.EXPECT().Close().Return(errors.New("close failed")).Once()
	healthy := newStartedMockSource(t)

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{failing, healthy},
	)
	require.NoError(t, err)

	multi.Start(context.Background())
	require.NoError(t, multi.Close())
	healthy.AssertCalled(t, "Close")
}

func TestMultiSourceMessageDiscovery_StartIsExecutedOnce(t *testing.T) {
	sourceA := newStartedMockSource(t)
	sourceB := newStartedMockSource(t)

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	multi.Start(ctx)
	multi.Start(ctx)

	sourceA.AssertNumberOfCalls(t, "Start", 1)
	sourceB.AssertNumberOfCalls(t, "Start", 1)
}

func TestMultiSourceMessageDiscovery_RejectsNilSources(t *testing.T) {
	validSource := mocks.NewMockMessageDiscovery(t)

	tests := []struct {
		name    string
		sources []common.MessageDiscovery
		wantErr string
	}{
		{
			name:    "single nil source",
			sources: []common.MessageDiscovery{nil},
			wantErr: "source is nil",
		},
		{
			name:    "nil source among valid sources",
			sources: []common.MessageDiscovery{validSource, nil},
			wantErr: "source is nil",
		},
		{
			name:    "empty sources",
			sources: []common.MessageDiscovery{},
			wantErr: "at least one discovery source is required",
		},
		{
			name:    "nil sources slice",
			sources: nil,
			wantErr: "at least one discovery source is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMultiSourceMessageDiscovery(logger.Test(t), tt.sources)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMultiSourceMessageDiscovery_RejectsNilLogger(t *testing.T) {
	source := mocks.NewMockMessageDiscovery(t)

	_, err := NewMultiSourceMessageDiscovery(nil, []common.MessageDiscovery{source})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestMultiSourceMessageDiscovery_ValidationErrorDoesNotStartSources(t *testing.T) {
	source := mocks.NewMockMessageDiscovery(t)
	source.EXPECT().Close().Return(nil).Maybe()

	_, err := NewMultiSourceMessageDiscovery(nil, []common.MessageDiscovery{source, nil})
	require.Error(t, err)

	source.AssertNotCalled(t, "Start", mock.Anything)
}

// validMinimalConfig returns a Config with valid Scheduler and Storage so we can test Discoveries validation in isolation.
func validMinimalConfig(discoveries []config.DiscoveryConfig) *config.Config {
	return &config.Config{
		Scheduler: config.SchedulerConfig{
			TickerInterval:               100,
			VerificationVisibilityWindow: 120,
			BaseDelay:                    1000,
			MaxDelay:                     5000,
		},
		Discoveries: discoveries,
		Storage: config.StorageConfig{
			Strategy: config.StorageStrategySingle,
			Single: &config.SingleStorageConfig{
				Type: config.StorageBackendTypePostgres,
				Postgres: &config.PostgresConfig{
					URI:                "postgresql://test:test@localhost:5432/test",
					MaxOpenConnections: 10,
					MaxIdleConnections: 5,
				},
			},
		},
	}
}

func TestConfig_Validate_Discoveries(t *testing.T) {
	tests := []struct {
		name        string
		discoveries []config.DiscoveryConfig
		wantErr     bool
	}{
		{
			name:        "zero discoveries returns error",
			discoveries: nil,
			wantErr:     true,
		},
		{
			name:        "empty discoveries returns error",
			discoveries: []config.DiscoveryConfig{},
			wantErr:     true,
		},
		{
			name: "one valid discovery succeeds",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
			},
			wantErr: false,
		},
		{
			name: "two valid discoveries succeed",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg2", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
			},
			wantErr: false,
		},
		{
			name: "discovery with missing address fails",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
			},
			wantErr: true,
		},
		{
			name: "discovery with empty NtpServer fails",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "",
				},
			},
			wantErr: true,
		},
		{
			name: "two discoveries with same address returns duplicate error",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
					NtpServer:              "time.google.com",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validMinimalConfig(tt.discoveries)
			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.name == "two discoveries with same address returns duplicate error" {
					assert.Contains(t, err.Error(), "duplicate")
					assert.Contains(t, err.Error(), "http://agg1")
				}
				return
			}
			require.NoError(t, err)
		})
	}
}
