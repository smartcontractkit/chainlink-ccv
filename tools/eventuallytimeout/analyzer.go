// Package eventuallytimeout implements a static analysis that rejects short,
// compile-time-constant timeouts in Testify Eventually assertions.
package eventuallytimeout

import (
	"go/ast"
	"go/constant"
	"go/types"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const minTimeout = 10 * time.Second

var testifyPackages = map[string]bool{
	"github.com/stretchr/testify/assert":  true,
	"github.com/stretchr/testify/require": true,
}

var eventuallyFunctions = map[string]bool{
	"Eventually":       true,
	"Eventuallyf":      true,
	"EventuallyWithT":  true,
	"EventuallyWithTf": true,
}

// Analyzer is the go/analysis entry point.
var Analyzer = &analysis.Analyzer{
	Name:     "eventuallytimeout",
	Doc:      "reports Testify Eventually timeouts shorter than 10 seconds; use tests.WaitTimeout(t) or a longer timeout",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector) //nolint:errcheck,revive // guaranteed by Requires
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(node ast.Node) {
		call := node.(*ast.CallExpr) //nolint:errcheck,revive // nodeFilter only matches *ast.CallExpr
		name, timeoutIndex, ok := eventuallyCall(pass, call)
		if !ok || len(call.Args) <= timeoutIndex {
			return
		}
		timeout, ok := constantDuration(pass, call.Args[timeoutIndex])
		if !ok || timeout >= minTimeout {
			return
		}
		pass.Reportf(call.Args[timeoutIndex].Pos(),
			"%s timeout %s is shorter than the %s minimum; use tests.WaitTimeout(t) or a longer timeout",
			name, timeout, minTimeout)
	})
	return nil, nil
}

func eventuallyCall(pass *analysis.Pass, call *ast.CallExpr) (string, int, bool) {
	var ident *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	default:
		return "", 0, false
	}
	fn, ok := pass.TypesInfo.ObjectOf(ident).(*types.Func)
	if !ok || fn.Pkg() == nil || !testifyPackages[fn.Pkg().Path()] || !eventuallyFunctions[fn.Name()] {
		return "", 0, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return "", 0, false
	}
	if sig.Recv() != nil {
		return fn.Name(), 1, true
	}
	return fn.Name(), 2, true
}

func constantDuration(pass *analysis.Pass, expr ast.Expr) (time.Duration, bool) {
	value := pass.TypesInfo.Types[expr].Value
	if value == nil {
		return 0, false
	}
	nanoseconds, ok := constant.Int64Val(constant.ToInt(value))
	return time.Duration(nanoseconds), ok
}
