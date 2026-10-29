package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// servicesService aliases the interface used for per-chain source readers.
type servicesService = services.Service

// fakeSourceReaderService is a minimal services.Service whose Start can be
// made to fail, standing in for a per-chain source reader.
type fakeSourceReaderService struct {
	name     string
	startErr error
	readyErr error
	started  bool
}

func (f *fakeSourceReaderService) Start(context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	return nil
}

func (f *fakeSourceReaderService) Close() error { return nil }
func (f *fakeSourceReaderService) Name() string { return f.name }
func (f *fakeSourceReaderService) Ready() error { return f.readyErr }
func (f *fakeSourceReaderService) HealthReport() map[string]error {
	return map[string]error{f.name: f.readyErr}
}

// One chain failing to start must not stop the others, and the failure must
// stay visible in Degraded and the health report.
func TestCoordinator_Start_SkipsFailedSourceReader(t *testing.T) {
	const (
		badChain  protocol.ChainSelector = 1
		goodChain protocol.ChainSelector = 2
	)
	bad := &fakeSourceReaderService{name: "bad", startErr: errors.New("RPC down")}
	good := &fakeSourceReaderService{name: "good"}

	vc := &Coordinator{
		lggr:                  logger.Test(t),
		verifierID:            "test-verifier",
		monitoring:            &noopMonitoring{},
		sourceReaderServices:  map[protocol.ChainSelector]servicesService{badChain: bad, goodChain: good},
		sourceReaderStartErrs: make(map[protocol.ChainSelector]error),
	}

	require.NoError(t, vc.Start(t.Context()))
	defer func() { require.NoError(t, vc.Close()) }()

	require.True(t, good.started, "healthy chain must start despite the failed one")
	require.ErrorContains(t, vc.sourceReaderStartErrs[badChain], "RPC down")
	require.NotContains(t, vc.sourceReaderServices, badChain, "failed chain is removed from the active set")

	// The skipped chain degrades the coordinator. Ready stays nil so /health/ready keeps
	// returning 200, and Degraded plus the health report name the skipped chain.
	require.NoError(t, vc.Ready())
	require.ErrorContains(t, vc.Degraded(), "1 source reader(s) skipped at startup")
	require.ErrorContains(t, vc.Degraded(), "SourceReader[1]: RPC down")

	report := vc.HealthReport()
	require.ErrorContains(t, report["verifier.Coordinator[test-verifier].SourceReader[1]"], "RPC down")
	require.ErrorContains(t, report["verifier.Coordinator[test-verifier]"], "skipped at startup")
}

// A running chain whose source reader is not ready (e.g. its RPC is down) degrades the
// coordinator, and it recovers on its own once the reader becomes ready.
func TestCoordinator_DegradedWhenSourceReaderNotReady(t *testing.T) {
	down := &fakeSourceReaderService{name: "down", readyErr: errors.New("start block not yet initialized")}
	vc := &Coordinator{
		lggr:       logger.Test(t),
		verifierID: "test-verifier",
		monitoring: &noopMonitoring{},
		sourceReaderServices: map[protocol.ChainSelector]servicesService{
			1: down,
			2: &fakeSourceReaderService{name: "up"},
		},
		sourceReaderStartErrs: make(map[protocol.ChainSelector]error),
	}
	require.NoError(t, vc.Start(t.Context()))
	defer func() { require.NoError(t, vc.Close()) }()

	require.NoError(t, vc.Ready(), "one ready chain keeps the coordinator ready")
	require.ErrorContains(t, vc.Degraded(), "1 source reader(s) not ready")
	require.ErrorContains(t, vc.Degraded(), "SourceReader[1]: start block not yet initialized")
	require.NotContains(t, vc.Degraded().Error(), "SourceReader[2]")
	require.ErrorContains(t, vc.HealthReport()["verifier.Coordinator[test-verifier]"], "not ready")

	down.readyErr = nil
	require.NoError(t, vc.Degraded(), "a recovered chain no longer degrades the coordinator")
}

// With every chain running but none ready there is nothing to verify, so the coordinator is NotReady.
func TestCoordinator_NotReadyWhenNoSourceReaderReady(t *testing.T) {
	vc := &Coordinator{
		lggr:       logger.Test(t),
		verifierID: "test-verifier",
		monitoring: &noopMonitoring{},
		sourceReaderServices: map[protocol.ChainSelector]servicesService{
			1: &fakeSourceReaderService{name: "a", readyErr: errors.New("RPC down")},
			2: &fakeSourceReaderService{name: "b", readyErr: errors.New("RPC down")},
		},
		sourceReaderStartErrs: make(map[protocol.ChainSelector]error),
	}
	require.NoError(t, vc.Start(t.Context()))
	defer func() { require.NoError(t, vc.Close()) }()

	require.ErrorContains(t, vc.Ready(), "no source reader is ready across 2 chain(s)")
	require.ErrorContains(t, vc.Ready(), "SourceReader[1]: RPC down")
	require.ErrorContains(t, vc.HealthReport()["verifier.Coordinator[test-verifier]"], "no source reader is ready")
}

// If the only configured chain cannot get a source reader service there is nothing
// to coordinate, so creating the source readers fails instead of starting an empty coordinator.
func TestCreateSourceReadersDB_FailsWhenNoServiceCanBeCreated(t *testing.T) {
	const chain protocol.ChainSelector = 1
	config := CoordinatorConfig{SourceConfigs: map[protocol.ChainSelector]vtypes.SourceConfig{chain: {}}}

	// A nil source reader makes sourcereader.NewService fail for the only chain.
	_, _, err := createSourceReadersDB(
		logger.Test(t), config, nil, nil, nil,
		map[protocol.ChainSelector]chainaccess.SourceReader{chain: nil}, nil, nil, nil, nil,
	)
	require.ErrorContains(t, err, "no source reader service could be created for 1 configured chain(s)")
	require.ErrorContains(t, err, "sourceReader cannot be nil")
}

// If every chain fails to start there is nothing to coordinate: that remains fatal.
func TestCoordinator_Start_FailsWhenNoSourceReaderStarts(t *testing.T) {
	vc := &Coordinator{
		lggr:       logger.Test(t),
		verifierID: "test-verifier",
		monitoring: &noopMonitoring{},
		sourceReaderServices: map[protocol.ChainSelector]servicesService{
			1: &fakeSourceReaderService{name: "a", startErr: errors.New("RPC down")},
			2: &fakeSourceReaderService{name: "b", startErr: errors.New("RPC down")},
		},
		sourceReaderStartErrs: make(map[protocol.ChainSelector]error),
	}

	err := vc.Start(t.Context())
	require.ErrorContains(t, err, "failed to start any source reader service")
}
