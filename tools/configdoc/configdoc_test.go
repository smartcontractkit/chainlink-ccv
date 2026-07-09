package configdoc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestModulePath covers the go.mod module-directive parsing used by NewGenerator.
func TestModulePath(t *testing.T) {
	p, err := modulePath([]byte("module github.com/foo/bar\n\ngo 1.24\n"))
	require.NoError(t, err)
	require.Equal(t, "github.com/foo/bar", p)

	_, err = modulePath([]byte("go 1.24\n\nrequire example.com/x v1.0.0\n"))
	require.Error(t, err)
}

// TestNewGeneratorFindsModule proves NewGenerator walks up from a nested
// directory to the enclosing go.mod and roots the Generator there.
func TestNewGeneratorFindsModule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.24\n"), 0o600))
	sub := filepath.Join(dir, "a", "b")
	require.NoError(t, os.MkdirAll(sub, 0o755))

	g, err := NewGenerator(sub)
	require.NoError(t, err)
	require.Equal(t, "example.com/x", g.ModulePath)

	// ModuleRoot is the dir holding go.mod (resolve symlinks: macOS TMPDIR is one).
	wantRoot, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	gotRoot, err := filepath.EvalSymlinks(g.ModuleRoot)
	require.NoError(t, err)
	require.Equal(t, wantRoot, gotRoot)
}

// TestNewGeneratorNoModule errors when no go.mod exists at or above dir.
func TestNewGeneratorNoModule(t *testing.T) {
	_, err := NewGenerator(t.TempDir())
	require.Error(t, err)
}
