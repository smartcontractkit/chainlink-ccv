package quiesce

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeProc builds a fake proc root: pid dir -> comm content.
func writeProc(t *testing.T, comms map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, comm := range comms {
		dir := filepath.Join(root, strconv.Itoa(pid))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644))
	}
	// Non-numeric and unreadable entries must be skipped, not fatal.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys"), 0o755))
	return root
}

func TestFindServicePIDPicksLowestMatchingPID(t *testing.T) {
	root := writeProc(t, map[int]string{1: "tini", 2: "verifier", 7: "verifier"})
	pid, err := findServicePID(root, 99, "verifier")
	require.NoError(t, err)
	require.Equal(t, 2, pid)
}

func TestFindServicePIDExcludesSelf(t *testing.T) {
	root := writeProc(t, map[int]string{2: "verifier", 7: "verifier"})
	pid, err := findServicePID(root, 2, "verifier")
	require.NoError(t, err)
	require.Equal(t, 7, pid)
}

func TestFindServicePIDNoMatch(t *testing.T) {
	root := writeProc(t, map[int]string{1: "tini"})
	_, err := findServicePID(root, 99, "verifier")
	require.ErrorContains(t, err, "no running verifier service")
}

func TestSignalServiceTargetsServiceNotSelf(t *testing.T) {
	// The test binary's comm is "quiesce.test", matching ownName().
	root := writeProc(t, map[int]string{1: "tini", 5: "quiesce.test"})

	var gotPID int
	var gotSig syscall.Signal
	orig := kill
	kill = func(pid int, sig syscall.Signal) error {
		gotPID, gotSig = pid, sig
		return nil
	}
	t.Cleanup(func() { kill = orig })

	require.NoError(t, signalService(root, syscall.SIGSTOP))
	require.Equal(t, 5, gotPID)
	require.Equal(t, syscall.SIGSTOP, gotSig)
}
