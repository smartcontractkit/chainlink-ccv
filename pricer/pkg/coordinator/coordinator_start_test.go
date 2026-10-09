package coordinator

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pricer "github.com/smartcontractkit/chainlink-ccv/pricer/pkg"
	ks "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	core "github.com/smartcontractkit/chainlink-common/pkg/types/core"
)

// fakeChain stands in for a pricer.Chain whose Start can be made to fail.
type fakeChain struct {
	startErr error
	started  bool
	closed   bool
}

func (f *fakeChain) Start(context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	return nil
}

func (f *fakeChain) Tick(context.Context) error { return nil }

func (f *fakeChain) CreateKeystore(context.Context, ks.KMSConfig, []byte, string) (core.Keystore, error) {
	return nil, nil
}

func (f *fakeChain) Close() error {
	f.closed = true
	return nil
}

func newTestPricer(t *testing.T, chains map[protocol.ChainSelector]pricer.Chain) *Pricer {
	t.Helper()
	return &Pricer{
		lggr:           logger.Test(t),
		cfg:            Config{Interval: *config.MustNewDuration(time.Hour)}, // no ticks during the test
		done:           make(chan struct{}),
		chainStartErrs: make(map[protocol.ChainSelector]error),
		httpServer:     &http.Server{Addr: "127.0.0.1:0"},
		chains:         chains,
	}
}

// One failing chain must not stop the healthy one; the failure stays visible
// in Ready (so /health pages) and HealthReport, and the failed chain is
// skipped from Close.
func TestPricer_Start_SkipsFailedChain(t *testing.T) {
	const (
		badChain  protocol.ChainSelector = 1
		goodChain protocol.ChainSelector = 2
	)
	bad := &fakeChain{startErr: errors.New("RPC down")}
	good := &fakeChain{}

	p := newTestPricer(t, map[protocol.ChainSelector]pricer.Chain{
		badChain:  bad,
		goodChain: good,
	})

	require.NoError(t, p.Start(t.Context()))
	defer func() { require.NoError(t, p.Close()) }()

	require.True(t, good.started, "healthy chain must start despite the failed one")
	require.False(t, bad.started)
	require.NotContains(t, p.chains, badChain, "failed chain is removed from the active set")

	// The skipped chain must make the whole service NotReady so /health/ready
	// returns 503 and pages.
	require.ErrorContains(t, p.Ready(), "1 chain(s) skipped at startup")
	require.ErrorContains(t, p.Ready(), "RPC down")

	report := p.HealthReport()
	require.ErrorContains(t, report["pricer.Pricer"], "skipped at startup")
	require.ErrorContains(t, report["pricer.Pricer.Chain[1]"], "RPC down")
}

// With no skips the pricer is Ready after Start.
func TestPricer_Ready_NoSkipsAfterStart(t *testing.T) {
	p := newTestPricer(t, map[protocol.ChainSelector]pricer.Chain{1: &fakeChain{}})

	require.Error(t, p.Ready(), "not started yet")
	require.NoError(t, p.Start(t.Context()))
	defer func() { require.NoError(t, p.Close()) }()

	require.NoError(t, p.Ready())
	require.NoError(t, p.HealthReport()["pricer.Pricer"])
}

// If every chain fails there is nothing to price: Start fails.
func TestPricer_Start_FailsWhenNoChainStarts(t *testing.T) {
	p := newTestPricer(t, map[protocol.ChainSelector]pricer.Chain{
		1: &fakeChain{startErr: errors.New("RPC down")},
		2: &fakeChain{startErr: errors.New("RPC down")},
	})

	err := p.Start(t.Context())
	require.ErrorContains(t, err, "failed to start any chain")
}

// Close must close the chains that started (and only those).
func TestPricer_Close_ClosesStartedChains(t *testing.T) {
	const (
		badChain  protocol.ChainSelector = 1
		goodChain protocol.ChainSelector = 2
	)
	bad := &fakeChain{startErr: errors.New("RPC down")}
	good := &fakeChain{}

	p := newTestPricer(t, map[protocol.ChainSelector]pricer.Chain{
		badChain:  bad,
		goodChain: good,
	})

	require.NoError(t, p.Start(t.Context()))
	require.NoError(t, p.Close())

	require.True(t, good.closed, "started chain must be closed")
	require.False(t, bad.closed, "skipped chain was never started, nothing to close")
}
