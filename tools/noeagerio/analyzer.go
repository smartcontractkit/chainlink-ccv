// Package noeagerio implements a static analysis that flags I/O performed
// inside startup paths: constructors (exported New* functions) and Start
// methods. Startup I/O has repeatedly caused outages in this repo — a hanging
// or failing RPC/DB call in a constructor or Start blocks or aborts process
// startup, and a single bad chain can take down every healthy one.
//
// I/O belongs at query time (see common/lazy for cached-on-success derivation)
// or in a background goroutine that reports its state via Ready/HealthReport.
// Deliberate exceptions need a justified //nolint:noeagerio comment.
package noeagerio

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the go/analysis entry point.
var Analyzer = &analysis.Analyzer{
	Name:     "noeagerio",
	Doc:      "reports I/O calls in constructors (New*) and Start methods; defer I/O to query time or background goroutines",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

// denyFuncs are package-level functions that perform network/DB I/O, keyed by
// "import/path.Name".
var denyFuncs = map[string]string{
	"net/http.Get":                                          "issues an HTTP request",
	"net/http.Head":                                         "issues an HTTP request",
	"net/http.Post":                                         "issues an HTTP request",
	"net/http.PostForm":                                     "issues an HTTP request",
	"github.com/jmoiron/sqlx.Connect":                       "opens and pings a database connection",
	"github.com/jmoiron/sqlx.ConnectContext":                "opens and pings a database connection",
	"github.com/jmoiron/sqlx.MustConnect":                   "opens and pings a database connection",
	"google.golang.org/grpc.Dial":                           "dials a gRPC endpoint",
	"google.golang.org/grpc.DialContext":                    "dials a gRPC endpoint",
	"github.com/ethereum/go-ethereum/ethclient.Dial":        "dials an Ethereum RPC endpoint",
	"github.com/ethereum/go-ethereum/ethclient.DialContext": "dials an Ethereum RPC endpoint",
	"github.com/jackc/pgx/v5.Connect":                       "opens a database connection",
	"github.com/jackc/pgx/v5/pgxpool.Connect":               "opens a database connection",
	// Repo entrypoints whose I/O happens across a package boundary and so
	// cannot be found by local taint propagation.
	"github.com/smartcontractkit/chainlink-ccv/common.EnsureDBConnection":                            "pings the database",
	"github.com/smartcontractkit/chainlink-ccv/common.EnsureDBConnectionContext":                     "pings the database",
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db.RunPostgresMigrations":                "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db.RunPostgresMigrationsContext":         "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db.RunMigrations":                           "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db.RunMigrationsContext":                    "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage.RunMigrations":                    "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage.RunMigrationsContext":             "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres.RunMigrations":        "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres.RunMigrationsContext": "runs database migrations",
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage.NewPostgresStorage":               "opens a database connection",
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/replay.NewStoreFromConfig":                "opens a database connection",
}

// denyMethods are methods that perform network/DB I/O, matched by name. An
// entry of the form "Name@substr" additionally requires the receiver type's
// string to contain substr (for generic names like Ping or Get).
var denyMethods = map[string]string{
	"Dial":                       "dials a remote endpoint",
	"DialContext":                "dials a remote endpoint",
	"CallContext":                "issues an RPC call",
	"CallContract":               "issues an RPC call",
	"HeaderByNumber":             "fetches a block header over RPC",
	"HeaderByHash":               "fetches a block header over RPC",
	"BlockByNumber":              "fetches a block over RPC",
	"BlockByHash":                "fetches a block over RPC",
	"TransactionReceipt":         "fetches a receipt over RPC",
	"TransactionByHash":          "fetches a transaction over RPC",
	"SendTransaction":            "sends a transaction over RPC",
	"BalanceAt":                  "queries chain state over RPC",
	"CodeAt":                     "queries chain state over RPC",
	"NonceAt":                    "queries chain state over RPC",
	"PendingNonceAt":             "queries chain state over RPC",
	"ChainID":                    "queries the chain over RPC",
	"SyncProgress":               "queries the chain over RPC",
	"SuggestGasPrice":            "queries the chain over RPC",
	"SuggestGasTipCap":           "queries the chain over RPC",
	"EstimateGas":                "queries the chain over RPC",
	"FilterLogs":                 "queries logs over RPC",
	"SubscribeFilterLogs":        "subscribes to logs over RPC",
	"LatestBlock":                "fetches the latest block over RPC",
	"LatestAndFinalizedBlock":    "fetches blocks over RPC",
	"LatestFinalizedBlock":       "fetches the finalized block over RPC",
	"LatestSafeBlock":            "fetches the safe block over RPC",
	"FetchMessageSentEvents":     "fetches logs over RPC",
	"GetRMNCursedSubjects":       "reads an RMN Remote over RPC",
	"GetStaticConfig":            "reads contract state over RPC",
	"GetDestChainConfig":         "reads contract state over RPC",
	"GetAccessor":                "constructs a chain accessor (dials RPC, starts chain services)",
	"ReadChainStatuses":          "reads from the database",
	"WriteChainStatuses":         "writes to the database",
	"GetDiscoverySequenceNumber": "reads from the database",
	"CreateDiscoveryState":       "writes to the database",
	"LoadJob":                    "reads from the database",
	"RunMigrations":              "runs database migrations",
	"RunPostgresMigrations":      "runs database migrations",
	"EnsureDBConnection":         "pings the database",
	"EnabledAddresses":           "reads from the keystore",
	"GetKeys":                    "reads from the keystore",
	"EnsureKey":                  "writes to the keystore",
	"EnsureImportedKey":          "writes to the keystore",
	"LoadKeystore":               "reads from the keystore",
	"GetPublicKey":               "queries the KMS",
	"LoadKMSKeystore":            "queries the KMS",
	// Known repo entrypoints whose I/O happens across a package boundary and so
	// cannot be found by local taint propagation.
	"New@sqlutil/pg":            "opens a database connection",
	"CreateStorage@pkg/storage": "opens and migrates database storage",
}

// goroutineAPIs are method-name/receiver-substring pairs for the APIs known to
// launch a function literal on a background goroutine. I/O inside those
// literals does not block startup, so it is exempt. Name lookalikes on other
// receivers are not exempt.
var goroutineAPIs = map[string][]string{
	"Go": {"sync.WaitGroup", "errgroup.Group"},
}

// syncCallbackInvokers are methods known to invoke a function-literal argument
// synchronously (services.StateMachine Start/Stop run their callback inline),
// so those closure bodies are startup code. Closures passed to anything else
// are treated as created, not executed: their bodies are not walked.
var syncCallbackInvokers = map[string]bool{
	"StartOnce": true,
	"StopOnce":  true,
}

// lazyPath is the canonical query-time derivation helper: New only registers
// the closure, which runs (uncached-on-failure) at first use.
const lazyPath = "github.com/smartcontractkit/chainlink-ccv/common/lazy"

// justifiedNolint matches a noeagerio directive that carries a written
// justification: "nolint:noeagerio // <nonempty reason>". A bare directive, or
// a mere mention of one in prose, is not a suppression.
var justifiedNolint = regexp.MustCompile(`nolint:noeagerio\s*//\s*\S`)

// ioCall records a denylisted call site and why it was flagged.
type ioCall struct {
	pos    token.Pos
	reason string
}

// funcInfo accumulates what we know about one declared function or method.
type funcInfo struct {
	decl        *ast.FuncDecl
	obj         *types.Func
	ioCalls     []ioCall             // direct denylisted calls (outside spawned goroutines)
	callees     map[*types.Func]bool // local functions called outside spawned goroutines
	isStartup   bool
	startupKind string // "constructor" or "Start method"
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector) //nolint:errcheck,revive // guaranteed by Requires
	if insp == nil {
		return nil, nil
	}

	infos := make(map[*types.Func]*funcInfo)

	// Pass 1: for every declared function, collect its direct denylisted calls
	// and its edges to other in-package functions, skipping code that runs on
	// spawned goroutines or in not-yet-executed closures.
	nodeFilter := []ast.Node{(*ast.FuncDecl)(nil)}
	insp.Preorder(nodeFilter, func(n ast.Node) {
		decl := n.(*ast.FuncDecl) //nolint:errcheck,revive // nodeFilter only matches *ast.FuncDecl
		if isTestFile(pass, decl.Pos()) {
			return
		}
		obj, _ := pass.TypesInfo.Defs[decl.Name].(*types.Func) //nolint:revive // nil when the name declares no func
		if obj == nil {
			return
		}
		fi := &funcInfo{decl: decl, obj: obj, callees: make(map[*types.Func]bool)}
		fi.isStartup, fi.startupKind = classifyStartup(decl)
		forEachSyncCall(pass, decl, func(call *ast.CallExpr) {
			if reason, ok := denyReason(pass, call); ok {
				// A suppressed call is dropped entirely: the justification
				// covers it, so it must not taint callers up the chain.
				if !suppressed(pass, fi.decl, call.Pos()) {
					fi.ioCalls = append(fi.ioCalls, ioCall{pos: call.Pos(), reason: reason})
				}
			}
			if callee := localFunc(pass, call); callee != nil && !suppressed(pass, fi.decl, call.Pos()) {
				fi.callees[callee] = true
			}
		})
		infos[obj] = fi
	})

	// Pass 2: propagate I/O reachability through the local call graph until a
	// fixed point. A function is tainted when it performs I/O itself or calls
	// (synchronously) a tainted in-package function.
	tainted := make(map[*types.Func]bool)
	for obj, fi := range infos {
		if len(fi.ioCalls) > 0 {
			tainted[obj] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for obj, fi := range infos {
			if tainted[obj] {
				continue
			}
			for callee := range fi.callees {
				if tainted[callee] {
					tainted[obj] = true
					changed = true
					break
				}
			}
		}
	}

	// Pass 3: report. Startup functions get their direct I/O calls flagged, and
	// calls into tainted local helpers flagged at the call site.
	for _, fi := range infos {
		if !fi.isStartup || !tainted[fi.obj] {
			continue
		}
		for _, c := range fi.ioCalls {
			pass.Reportf(c.pos,
				"I/O in %s %s: %s; constructors and Start must not perform I/O — defer to query time (common/lazy) or a background goroutine that reports via Ready/HealthReport",
				fi.startupKind, fi.decl.Name.Name, c.reason)
		}
		forEachSyncCall(pass, fi.decl, func(call *ast.CallExpr) {
			callee := localFunc(pass, call)
			if callee == nil || callee == fi.obj || !tainted[callee] {
				return
			}
			if suppressed(pass, fi.decl, call.Pos()) {
				return
			}
			reason := "performs I/O"
			if len(infos[callee].ioCalls) > 0 {
				reason = infos[callee].ioCalls[0].reason
			}
			pass.Reportf(call.Pos(),
				"%s %s calls %s, which performs I/O (%s); constructors and Start must not perform I/O — defer to query time (common/lazy) or a background goroutine that reports via Ready/HealthReport",
				fi.startupKind, fi.decl.Name.Name, callee.Name(), reason)
		})
	}
	return nil, nil
}

// forEachSyncCall walks the parts of fn's body that run synchronously when fn
// itself runs: immediate code, immediately-invoked closures, closures passed
// to known synchronous callback invokers, and the argument expressions of
// goroutine launches and deferred registrations (arguments are evaluated
// eagerly even when the callee is not). visit receives each synchronous call.
func forEachSyncCall(pass *analysis.Pass, decl *ast.FuncDecl, visit func(call *ast.CallExpr)) {
	if decl.Body == nil {
		return
	}
	// executed marks FuncLits whose bodies run synchronously.
	executed := make(map[*ast.FuncLit]bool)

	var inspector func(n ast.Node) bool
	inspector = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return executed[node]
		case *ast.GoStmt:
			// The launched call itself runs asynchronously; only its argument
			// expressions (e.g. `go consume(load())` -> load()) are evaluated now.
			for _, arg := range node.Call.Args {
				if _, isLit := arg.(*ast.FuncLit); isLit {
					continue
				}
				ast.Inspect(arg, inspector)
			}
			return false
		case *ast.CallExpr:
			fun := unwrapFun(node.Fun)
			if lit, ok := fun.(*ast.FuncLit); ok {
				executed[lit] = true // immediately-invoked closure
			}
			switch {
			case isGoroutineLaunch(pass, node), isDeferredRegistration(pass, node):
				// The call registers/launches a closure for later; only its
				// argument expressions are evaluated now.
				for _, arg := range node.Args {
					if _, isLit := arg.(*ast.FuncLit); isLit {
						continue
					}
					ast.Inspect(arg, inspector)
				}
				return false
			}
			if isSyncCallbackInvoker(node) {
				for _, arg := range node.Args {
					if lit, ok := arg.(*ast.FuncLit); ok {
						executed[lit] = true
					}
				}
			}
			visit(node)
			return true
		}
		return true
	}
	ast.Inspect(decl.Body, inspector)
}

// unwrapFun strips explicit type-argument wrappers (f[T](...)) from a call
// target so generic instantiations resolve like plain calls.
func unwrapFun(fun ast.Expr) ast.Expr {
	for {
		switch f := fun.(type) {
		case *ast.IndexExpr:
			fun = f.X
		case *ast.IndexListExpr:
			fun = f.X
		default:
			return fun
		}
	}
}

// isGoroutineLaunch reports whether the call launches a function literal on a
// background goroutine via a known API (sync.WaitGroup.Go, errgroup.Group.Go).
// Spelling alone is not enough: a synchronous lookalike method must stay
// visible to the analyzer.
func isGoroutineLaunch(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := unwrapFun(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receivers, known := goroutineAPIs[sel.Sel.Name]
	if !known {
		return false
	}
	hasFuncLit := false
	for _, arg := range call.Args {
		if _, isLit := arg.(*ast.FuncLit); isLit {
			hasFuncLit = true
			break
		}
	}
	if !hasFuncLit {
		return false
	}
	fn, ok := pass.TypesInfo.ObjectOf(sel.Sel).(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	sig, _ := fn.Type().(*types.Signature) //nolint:revive // methods always carry a *types.Signature
	if sig == nil || sig.Recv() == nil {
		return false
	}
	recv := sig.Recv().Type().String()
	for _, substr := range receivers {
		if strings.Contains(recv, substr) {
			return true
		}
	}
	return false
}

// isDeferredRegistration reports whether the call merely registers a function
// literal for execution at query time (common/lazy.New): the closure body is
// not startup code, and failures are not cached.
func isDeferredRegistration(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := unwrapFun(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := pass.TypesInfo.ObjectOf(sel.Sel).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Name() != "New" {
		return false
	}
	return fn.Pkg().Path() == lazyPath
}

// isSyncCallbackInvoker reports whether the call invokes its function-literal
// arguments synchronously (services.StateMachine runs Start/Stop callbacks
// inline), making those closure bodies startup code.
func isSyncCallbackInvoker(call *ast.CallExpr) bool {
	sel, ok := unwrapFun(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return syncCallbackInvokers[sel.Sel.Name]
}

// classifyStartup reports whether decl is a startup path: an exported
// constructor (New*) or a method named Start.
func classifyStartup(decl *ast.FuncDecl) (bool, string) {
	if decl.Recv != nil && decl.Name.Name == "Start" {
		return true, "Start method"
	}
	if decl.Recv == nil && strings.HasPrefix(decl.Name.Name, "New") && decl.Name.IsExported() {
		return true, "constructor"
	}
	return false, ""
}

// denyReason returns why a call is denylisted, if it is.
func denyReason(pass *analysis.Pass, call *ast.CallExpr) (string, bool) {
	sel, ok := unwrapFun(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	fn, ok := pass.TypesInfo.ObjectOf(sel.Sel).(*types.Func)
	if !ok {
		return "", false
	}
	sig, _ := fn.Type().(*types.Signature) //nolint:revive // *types.Func always carries a *types.Signature
	if sig == nil || sig.Recv() == nil {
		// Package-level function.
		if fn.Pkg() == nil {
			return "", false
		}
		reason, ok := denyFuncs[fn.Pkg().Path()+"."+fn.Name()]
		return reason, ok
	}
	// Method: match on name, plus an optional receiver-type substring.
	for entry, reason := range denyMethods {
		name, recvSubstr, _ := strings.Cut(entry, "@")
		if fn.Name() != name {
			continue
		}
		if recvSubstr == "" || strings.Contains(sig.Recv().Type().String(), recvSubstr) {
			return reason, true
		}
	}
	return "", false
}

// localFunc resolves a call to a function or method declared in the current
// package, so taint can propagate across helper boundaries.
func localFunc(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fun := unwrapFun(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return nil
	}
	fn, ok := pass.TypesInfo.ObjectOf(id).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg() != pass.Pkg {
		return nil
	}
	return fn
}

// suppressed reports whether a finding at pos carries a justified
// //nolint:noeagerio comment on its line, the line above, or the enclosing
// function's doc. Raw comment text is scanned because CommentGroup.Text()
// strips directives, and a directive without a written reason does not count.
func suppressed(pass *analysis.Pass, decl *ast.FuncDecl, pos token.Pos) bool {
	posn := pass.Fset.Position(pos)
	if decl.Doc != nil && groupHasNolint(decl.Doc) {
		return true
	}
	for _, file := range pass.Files {
		for _, cg := range file.Comments {
			end := pass.Fset.Position(cg.End())
			if end.Filename != posn.Filename {
				continue
			}
			if (end.Line == posn.Line || end.Line == posn.Line-1) && groupHasNolint(cg) {
				return true
			}
		}
	}
	return false
}

func groupHasNolint(cg *ast.CommentGroup) bool {
	for _, c := range cg.List {
		if justifiedNolint.MatchString(c.Text) {
			return true
		}
	}
	return false
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
