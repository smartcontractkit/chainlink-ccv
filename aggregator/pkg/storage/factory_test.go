package storage

import (
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newTestLogger(t *testing.T) logger.SugaredLogger {
	t.Helper()
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger.Sugared(lggr)
}

func TestFactory_CreateStorage_Memory(t *testing.T) {
	f := NewStorageFactory(newTestLogger(t))
	cfg := &model.StorageConfig{StorageType: model.StorageTypeMemory}

	s, err := f.CreateStorage(cfg, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if s == nil {
		t.Fatalf("expected non-nil storage")
	}
}

func TestFactory_CreateStorage_Unsupported(t *testing.T) {
	f := NewStorageFactory(newTestLogger(t))
	cfg := &model.StorageConfig{StorageType: "unsupported"}

	if _, err := f.CreateStorage(cfg, nil); err == nil {
		t.Fatalf("expected error for unsupported storage type")
	}
}

func TestFactory_CreateChainStatusStorage_Unsupported(t *testing.T) {
	f := NewStorageFactory(newTestLogger(t))
	cfg := &model.StorageConfig{StorageType: "unsupported"}

	if _, err := f.CreateChainStatusStorage(cfg, nil); err == nil {
		t.Fatalf("expected error for unsupported chain status storage type")
	}
}
