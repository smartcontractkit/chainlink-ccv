package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/common/health"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// One destination chain whose accessor fails at startup is skipped. The executor
// keeps running with the healthy chain, and /health reports degraded with the
// skipped chain named.
func TestFactory_Start_DegradedWhenOneChainFails(t *testing.T) {
	const (
		goodSelector protocol.ChainSelector = 5009297550715157269
		badSelector  protocol.ChainSelector = 3478487238524512106
	)

	good := mocks.NewMockAccessor(t)
	good.EXPECT().ContractTransmitter().Return(mocks.NewMockContractTransmitter(t), nil)
	good.EXPECT().DestinationReader().Return(mocks.NewMockDestinationReader(t), nil)
	fac := mocks.NewMockAccessorFactory(t)
	fac.EXPECT().GetAccessor(mock.Anything, goodSelector).Return(good, nil)
	fac.EXPECT().GetAccessor(mock.Anything, badSelector).Return(nil, errors.New("RPC down"))
	evmFactory = fac
	t.Cleanup(func() { evmFactory = nil })

	port := freeTCPPort(t)
	appConfig := fmt.Sprintf(`
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]
http_listen_port = %d

[chain_configuration."%d"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
execution_interval   = "1s"

[chain_configuration."%d"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
execution_interval   = "1s"
`, port, goodSelector, badSelector)

	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	require.NoError(t, f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg}))
	t.Cleanup(func() { assert.NoError(t, f.Stop(context.Background())) })

	client := &http.Client{Timeout: 3 * time.Second}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	var body health.ReadinessResponse
	require.Eventually(t, func() bool {
		resp, err := client.Get(healthURL)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&body) == nil
	}, 10*time.Second, 100*time.Millisecond, "executor /health did not answer 200")

	assert.Equal(t, health.Degraded, body.Status, "a skipped chain degrades the executor, it does not take it down")

	coordinator := findHealthService(t, body, "executor.Coordinator")
	assert.Equal(t, health.Ready, coordinator.Status, "the coordinator runs with the healthy chain")

	skips := findHealthService(t, body, "executor.StartupSkips")
	assert.Equal(t, health.Degraded, skips.Status)
	assert.Contains(t, skips.Error, fmt.Sprintf("Chain[%d]: RPC down", badSelector))
	assert.NotContains(t, skips.Error, fmt.Sprintf("Chain[%d]", goodSelector))
}

func findHealthService(t *testing.T, body health.ReadinessResponse, name string) health.ServicesHealth {
	t.Helper()
	for _, svc := range body.Services {
		if svc.Name == name {
			return svc
		}
	}
	require.Failf(t, "service missing from /health", "no service named %q in %+v", name, body.Services)
	return health.ServicesHealth{}
}
