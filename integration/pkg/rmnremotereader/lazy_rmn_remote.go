package rmnremotereader

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"
)

// LazyRMNRemoteCaller defers deriving and binding an RMN Remote contract caller
// until its first use at query time. This keeps constructors free of RPC calls
// that can fail (e.g. a transiently rate-limited provider), so building a source
// or destination reader never fails on an unavailable RPC.
//
// The derivation is performed once on the first successful call and cached
// thereafter. A failing derivation is NOT cached: the next call re-attempts, so
// the component self-heals as soon as the RPC recovers. Thread-safe.
type LazyRMNRemoteCaller struct {
	derive func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error)

	mu          sync.Mutex
	caller      rmn_remote.RMNRemoteCaller
	derivedOnce bool
}

// NewLazyRMNRemoteCaller builds a caller that derives the RMN Remote contract via
// derive on first use. derive must not be nil.
func NewLazyRMNRemoteCaller(derive func(ctx context.Context) (rmn_remote.RMNRemoteCaller, error)) *LazyRMNRemoteCaller {
	return &LazyRMNRemoteCaller{derive: derive}
}

// Caller returns the bound RMN Remote caller, deriving it on the first successful
// call. It returns an error until a derivation has succeeded; on a transient
// derivation failure it does not cache the error, so a later call retries.
func (l *LazyRMNRemoteCaller) Caller(ctx context.Context) (rmn_remote.RMNRemoteCaller, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.derivedOnce {
		caller, err := l.derive(ctx)
		if err != nil {
			return rmn_remote.RMNRemoteCaller{}, err
		}
		l.caller = caller
		l.derivedOnce = true
	}
	return l.caller, nil
}

// Derived reports whether a derivation has succeeded. Used only for tests.
func (l *LazyRMNRemoteCaller) Derived() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.derivedOnce
}
