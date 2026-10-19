package evm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Deleting, anchoring or replaying the log poller rewrites what every reader on the chain sees, so the
// reader is the only code allowed to do it. Any reference counts, including a method value.
func TestOnlyTheReaderMutatesTheLogPoller(t *testing.T) {
	mutating := map[string]bool{"DeleteLogsAndBlocksAfter": true, "SkipToBlock": true, "Replay": true}
	root := repoRoot(t)
	reader := filepath.Join(root, "integration", "pkg", "accessors", "evm", "evm_logpoller_source_reader.go")

	var offenders []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == reader {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && mutating[sel.Sel.Name] {
				offenders = append(offenders, fset.Position(sel.Sel.Pos()).String()+" "+sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, offenders, "only %s may delete, anchor or replay the log poller", reader)
}

// repoRoot returns the directory of the root go.mod, the module this package belongs to.
func repoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(data), "module github.com/smartcontractkit/chainlink-ccv\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "root go.mod not found")
		dir = parent
	}
}
