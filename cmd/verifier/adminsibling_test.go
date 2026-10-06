package verifier

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
)

// TestMain lets this test spawn the test binary as the console sibling: with
// the guard set, the child exits immediately, standing in for a console that
// stops cleanly.
func TestMain(m *testing.M) {
	if os.Getenv("CCV_ADMIN_SIBLING_CHILD") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStartAdminConsoleSibling(t *testing.T) {
	t.Run("absent config disables the sibling", func(t *testing.T) {
		t.Setenv(admin.ConfigPathEnv, filepath.Join(t.TempDir(), "missing.toml"))
		require.Nil(t, StartAdminConsoleSibling())
	})

	t.Run("present config starts a supervised sibling and stop terminates it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte("[console]\n"), 0o600))
		t.Setenv(admin.ConfigPathEnv, path)
		// The guard makes the spawned test binary exit cleanly, so the
		// supervisor sees a clean stop; the parent's stop must return promptly.
		t.Setenv("CCV_ADMIN_SIBLING_CHILD", "1")

		stop := StartAdminConsoleSibling()
		require.NotNil(t, stop)

		done := make(chan struct{})
		go func() {
			stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("stop did not terminate the sibling supervisor")
		}
	})
}
