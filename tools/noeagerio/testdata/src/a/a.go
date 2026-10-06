package a

import (
	"context"
	"net/http"
	"sync"

	"common/lazy"
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

// helper does I/O but is not itself a startup path, so it is not flagged
// directly; callers in startup paths are flagged instead.
func (s *service) helper() error {
	return s.d.Dial(context.Background())
}

// Start that calls a tainted helper is flagged at the call site.
func (s *service) Start(ctx context.Context) error {
	return s.helper() // want `Start method Start calls .*helper, which performs I/O`
}

// cleanService shows the blessed pattern: I/O happens in a spawned goroutine.
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

// nolintService documents a deliberate exception.
type nolintService struct {
	d *dialer
}

func (s *nolintService) Start(ctx context.Context) error {
	//nolint:noeagerio // fail-fast by design: this dependency is required for anything to work
	return s.d.Dial(ctx)
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

// lazyService defers its I/O to query time via common/lazy — the blessed
// pattern for values that need a derivation RPC.
type lazyService struct {
	addr *lazy.Lazy[string]
}

func NewLazyService(d *dialer) *lazyService {
	return &lazyService{
		addr: lazy.New(func(ctx context.Context) (string, error) {
			return "", d.Dial(ctx)
		}),
	}
}
