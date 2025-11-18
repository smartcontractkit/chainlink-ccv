package aggregator

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newTestLogger(t *testing.T) logger.SugaredLogger {
	t.Helper()
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.WarnLevel))
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger.Sugared(lggr)
}

func minimalConfig() *model.AggregatorConfig {
	return &model.AggregatorConfig{
		Server:       model.ServerConfig{Address: ":0"},
		Storage:      &model.StorageConfig{StorageType: model.StorageTypeMemory},
		Monitoring:   model.MonitoringConfig{Enabled: false},
		RateLimiting: model.RateLimitingConfig{Enabled: false},
		HealthCheck:  model.HealthCheckConfig{Enabled: false},
		Committees:   map[model.CommitteeID]*model.Committee{},
		StubMode:     true,
	}
}

func TestServer_StartStop_Memory(t *testing.T) {
	s := NewServer(newTestLogger(t), minimalConfig())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	if err := s.Start(lis); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	// Give the Run group a moment to spin
	time.Sleep(50 * time.Millisecond)
	if err := s.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

func TestServer_DoubleStart_ReturnsError(t *testing.T) {
	s := NewServer(newTestLogger(t), minimalConfig())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	if err := s.Start(lis); err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	if err := s.Start(lis); err == nil {
		t.Fatalf("expected error on second start")
	}
	_ = s.Stop()
}

func TestServer_Stop_WhenNotStarted_NoError(t *testing.T) {
	s := NewServer(newTestLogger(t), minimalConfig())
	if err := s.Stop(); err != nil {
		t.Fatalf("expected no error stopping non-started server, got %v", err)
	}
}
