package configuration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Success_MinimalMemory(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "agg.toml")
	content := `
[server]
  address = ":50051"

[storage]
  type = "memory"

[chainStatuses]
  maxChainStatusesPerRequest = 10

[rateLimiting]
  enabled = false

[committees]
  [committees.default]
    [committees.default.quorumConfigs]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg == nil || cfg.Server.Address != ":50051" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Storage == nil || string(cfg.Storage.StorageType) != "memory" {
		t.Fatalf("expected memory storage, got %+v", cfg.Storage)
	}
}

func TestLoadConfig_Error_FileMissing(t *testing.T) {
	if _, err := LoadConfig("/non/existent/file.toml"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}
