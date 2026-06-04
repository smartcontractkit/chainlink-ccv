package devenvruntime

import "testing"

func TestCheckConfigVersion(t *testing.T) {
	if err := CheckConfigVersion(1, 1); err != nil {
		t.Errorf("matching versions should be ok, got %v", err)
	}
	if err := CheckConfigVersion(2, 1); err == nil {
		t.Error("mismatched versions should error")
	}
	if err := CheckConfigVersion(0, 1); err == nil {
		t.Error("zero (missing) version should error")
	}
}
