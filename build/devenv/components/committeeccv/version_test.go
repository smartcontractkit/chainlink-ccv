package committeeccv

import "testing"

func TestDecodeConfigVersion(t *testing.T) {
	// version == Version: accepted, payload decoded.
	cfg, err := decodeConfig(map[string]any{
		"version":    int64(Version),
		"aggregator": []map[string]any{{"committee_name": "default"}},
	})
	if err != nil {
		t.Fatalf("version %d should be accepted: %v", Version, err)
	}
	if len(cfg.Aggregator) != 1 || cfg.Aggregator[0].CommitteeName != "default" {
		t.Fatalf("payload not decoded alongside version: %+v", cfg.Aggregator)
	}

	// wrong version: rejected.
	if _, err := decodeConfig(map[string]any{"version": int64(Version + 1)}); err == nil {
		t.Errorf("version %d should be rejected", Version+1)
	}

	// missing version (0): rejected.
	if _, err := decodeConfig(map[string]any{"aggregator": []map[string]any{}}); err == nil {
		t.Errorf("missing version should be rejected")
	}
}
