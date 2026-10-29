package a

import (
	"context"
	"net/http"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
)

// dialer is a stand-in for an RPC client; Dial is on the denylist by name.
type dialer struct{}

func (d *dialer) Dial(ctx context.Context) error { return nil }

type service struct {
	d  *dialer
	wg sync.WaitGroup
}

// Constructors that only assemble dependencies are fine.
func NewServiceClean(d *dialer) *service {
	return &service{d: d}
}

func NewServiceHTTP() *service {
	_, _ = http.Get("http://example.com") // want `I/O in constructor NewServiceHTTP: issues an HTTP request`
	return &service{}
}

func NewServiceDial() *service {
	s := &service{d: &dialer{}}
	_ = s.d.Dial(context.Background()) // want `I/O in constructor NewServiceDial: dials a remote endpoint`
	return s
}

// Cross-package denylisted functions are matched by import path.
func NewServiceDBPing() *service {
	_ = common.EnsureDBConnectionContext(context.Background(), nil) // want `I/O in constructor NewServiceDBPing: pings the database`
	return &service{}
}

// helper does I/O but is not itself a startup path, so it is not flagged
// directly; callers in startup paths are flagged instead.
func (s *service) helper() error {
	return s.d.Dial(context.Background())
}

// Start that calls a tainted helper is flagged at the call site.
func (s *service) Start(ctx context.Context) error {
	return s.helper() // want `Start method Start calls .*helper, which performs I/O`
}

// A suppressed call does not taint its callers: outerHelper wraps suppressed I/O.
func outerHelper(ctx context.Context) error {
	//nolint:noeagerio // deliberate fail-fast, documented here
	return helperIO(ctx)
}

func helperIO(ctx context.Context) error {
	_, err := http.Get("http://example.com")
	return err
}

// NewOuter calls a helper whose only I/O edge is suppressed: not flagged.
func NewOuter() *service {
	_ = outerHelper(context.Background())
	return &service{}
}

// Closures that are created but not executed are not walked: registering a
// callback performs no I/O, whatever the callback does.
func NewCallbackCreator(register func(func())) *service {
	register(func() {
		_, _ = http.Get("http://example.com") // not executed here
	})
	return &service{}
}

// Immediately-invoked closures run synchronously: their I/O is startup I/O.
func NewImmediateInvocation() *service {
	func() {
		_, _ = http.Get("http://example.com") // want `I/O in constructor NewImmediateInvocation: issues an HTTP request`
	}()
	return &service{}
}

// stateMachine mirrors services.StateMachine: StartOnce runs its callback inline.
type stateMachine struct{}

func (stateMachine) StartOnce(_ string, fn func() error) error { return fn() }

// Closures passed to known synchronous callback invokers are startup code.
func NewStartOnceCallback() *service {
	var sm stateMachine
	_ = sm.StartOnce("name", func() error {
		_, err := http.Get("http://example.com") // want `I/O in constructor NewStartOnceCallback: issues an HTTP request`
		return err
	})
	return &service{}
}

// Arguments of a goroutine launch are evaluated synchronously: load() runs now.
func load() error {
	_, err := http.Get("http://example.com")
	return err
}

func consume(_ error) {}

func NewGoStmtArgEvaluated() *service {
	go consume(load()) // want `constructor NewGoStmtArgEvaluated calls load, which performs I/O`
	return &service{}
}

// Arguments of a deferred registration are evaluated synchronously too: the
// registered closure itself is not walked, but makeDeriver runs now.
func makeDeriver() func(ctx context.Context) (string, error) {
	_, _ = http.Get("http://example.com")
	return func(context.Context) (string, error) { return "", nil }
}

func NewDeferredRegistration() *service {
	_ = lazy.New(makeDeriver()) // want `constructor NewDeferredRegistration calls makeDeriver, which performs I/O`
	return &service{}
}

// Generic instantiation must not lose the exemption: lazy.New[string] only
// registers the closure for query time.
func NewLazyGeneric(d *dialer) *service {
	_ = lazy.New[string](func(ctx context.Context) (string, error) {
		return "", d.Dial(ctx)
	})
	return &service{}
}

// A generic local helper called with explicit type arguments still records its
// I/O edge.
func genericHelper[T any](ctx context.Context) error {
	_, err := http.Get("http://example.com")
	return err
}

func NewGenericHelperCall() *service {
	_ = genericHelper[string](context.Background()) // want `constructor NewGenericHelperCall calls genericHelper, which performs I/O`
	return &service{}
}

// cleanService shows the blessed pattern: I/O happens on a spawned goroutine
// through a known goroutine API.
type cleanService struct {
	d  *dialer
	wg sync.WaitGroup
}

func (s *cleanService) Start(ctx context.Context) error {
	s.wg.Go(func() {
		_ = s.d.Dial(ctx)
	})
	go func() {
		_ = s.d.Dial(ctx)
	}()
	return nil
}

// lookalikePool.Go is synchronous but spelled like a goroutine API: it is not
// exempt (receiver is not sync.WaitGroup/errgroup.Group), though its uninvoked
// closure bodies are still treated as created, not executed.
type lookalikePool struct{}

func (p *lookalikePool) Go(f func()) { f() }

func (s *service) StartLookalike() {
	var p lookalikePool
	p.Go(func() {
		_, _ = http.Get("http://example.com") // created, not executed: no I/O runs here
	})
}

// nolintService documents a deliberate, justified exception.
type nolintService struct {
	d *dialer
}

func (s *nolintService) Start(ctx context.Context) error {
	//nolint:noeagerio // fail-fast by design: this dependency is required for anything to work
	return s.d.Dial(ctx)
}

// A bare directive without a written reason is not a suppression.
type bareNolintService struct {
	d *dialer
}

func (s *bareNolintService) Start(ctx context.Context) error {
	//nolint:noeagerio
	return s.d.Dial(ctx) // want `I/O in Start method Start: dials a remote endpoint`
}

// registry stands in for chainaccess registries: GetAccessor is denylisted by
// bare method name because accessor construction dials the chain.
type registry struct{}

func (r *registry) GetAccessor(ctx context.Context, selector uint64) (*dialer, error) {
	return &dialer{}, nil
}

type factoryService struct {
	reg *registry
}

func (s *factoryService) Start(ctx context.Context) error {
	_, err := s.reg.GetAccessor(ctx, 1) // want `I/O in Start method Start: constructs a chain accessor`
	return err
}

// unexported constructors are not flagged (callers own the policy), and
// neither are non-startup functions.
func newUnexported(d *dialer) *service {
	_ = d.Dial(context.Background())
	return &service{d: d}
}

func queryTime(ctx context.Context, d *dialer) error {
	_, err := http.Get("http://example.com")
	_ = d.Dial(ctx)
	return err
}
