package evm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	logPollerImport = "github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	adapterImport   = "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
)

// guard names the files allowed to reference a name. A scope narrows the guard to the files it
// accepts, for a name that other code legitimately uses for something else.
type guard struct {
	allowed []string
	scope   func(path string, file *ast.File) bool
}

func importsPackage(file *ast.File, path string) bool {
	return slices.ContainsFunc(file.Imports, func(spec *ast.ImportSpec) bool { return spec.Path.Value == `"`+path+`"` })
}

// Deleting, anchoring or replaying the log poller rewrites what every reader on the chain sees, so
// each of those has one owner: the reader anchors and replays, and the operator file deletes and
// searches for the common ancestor. Any reference counts, including a method value.
func TestOnlyTheReaderMutatesTheLogPoller(t *testing.T) {
	root := repoRoot(t)
	adapter := filepath.Join(root, "integration", "pkg", "accessors", "evm")
	reader := filepath.Join(adapter, "evm_logpoller_source_reader.go")
	operator := filepath.Join(adapter, "evm_logpoller_operator.go")

	offenders := referencesOutside(t, root, false, map[string]guard{
		"DeleteLogsAndBlocksAfter": {allowed: []string{operator}},
		// The CLI's Operator interface has a method of the same name, so only code that can reach the
		// LogPoller is held to it.
		"FindLCA":     {allowed: []string{operator}, scope: func(_ string, file *ast.File) bool { return importsPackage(file, logPollerImport) }},
		"SkipToBlock": {allowed: []string{reader}},
		"Replay":      {allowed: []string{reader}},
	})
	require.Empty(t, offenders, "only %s may delete or search, and only %s may anchor or replay the log poller", operator, reader)
}

// The operator functions are for the CLI: the running verifier service never deletes, so nothing
// under verifier/** or the in-node constructors may reach them.
func TestOnlyTheCLIWiringCallsTheOperatorFunctions(t *testing.T) {
	root := repoRoot(t)
	adapter := filepath.Join(root, "integration", "pkg", "accessors", "evm")
	operator := filepath.Join(adapter, "evm_logpoller_operator.go")
	wiring := filepath.Join(adapter, "cli", "blocks", "operator.go")
	allowed := []string{operator, wiring}

	offenders := referencesOutside(t, root, true, map[string]guard{
		"RemoveBlocksFrom": {allowed: allowed},
		// The CLI's Operator interface has a method of the same name, so only code in or importing the
		// adapter is held to it.
		"FindLCA": {allowed: allowed, scope: func(path string, file *ast.File) bool {
			return filepath.Dir(path) == adapter || importsPackage(file, adapterImport)
		}},
	})
	require.Empty(t, offenders, "only %s may call the operator functions", wiring)
}

// referencesOutside lists every non-test reference to a guarded name from a file its guard does not
// allow. A reference is a selector, such as a method value, and with identifiers set also a bare name,
// which is how code inside the declaring package calls a function. Declarations do not count.
func referencesOutside(t *testing.T, root string, identifiers bool, guards map[string]guard) []string {
	t.Helper()
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		report := func(id *ast.Ident) {
			g, guarded := guards[id.Name]
			if !guarded || slices.Contains(g.allowed, path) || (g.scope != nil && !g.scope(path, file)) {
				return
			}
			offenders = append(offenders, fset.Position(id.Pos()).String()+" "+id.Name)
		}
		skip := make(map[*ast.Ident]bool)
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				skip[n.Name] = true
			case *ast.SelectorExpr:
				skip[n.Sel] = true
				report(n.Sel)
			case *ast.Ident:
				if identifiers && !skip[n] {
					report(n)
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	return offenders
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
