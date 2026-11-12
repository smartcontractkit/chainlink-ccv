package static

import "testing"

// The build injects both values together; a half-injected build is a configuration bug.
// The repo-hygiene workflow runs this test with values injected, since a broken -ldflags
// path fails silently.
func TestInjectedTogether(t *testing.T) {
	t.Logf("Version=%q Sha=%q", Version, Sha)
	if (Version == Unset) != (Sha == Unset) {
		t.Fatalf("Version=%q Sha=%q: inject the values together or not at all", Version, Sha)
	}
}
