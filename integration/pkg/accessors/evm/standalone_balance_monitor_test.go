package evm

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys/keystest"
	evmmonitor "github.com/smartcontractkit/chainlink-evm/pkg/monitor"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

const testBalanceMonitorKeyName = "evm/tx/executor_evm_transmitter_key"

var testBalanceMonitorAddress = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

type balanceMonitorTestClient struct {
	client.Client
	balance      atomic.Int64
	calls        chan common.Address
	callContract func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
}

func (*balanceMonitorTestClient) ConfiguredChainID() *big.Int { return big.NewInt(1337) }

func (c *balanceMonitorTestClient) BalanceAt(ctx context.Context, address common.Address, _ *big.Int) (*big.Int, error) {
	select {
	case c.calls <- address:
		return big.NewInt(c.balance.Load()), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *balanceMonitorTestClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if c.callContract == nil {
		return nil, errors.New("unexpected contract call")
	}
	return c.callContract(ctx, msg, blockNumber)
}

func (*balanceMonitorTestClient) Close() {}

type balanceMonitorTestTXM struct {
	txmgr.TxManager
}

func (*balanceMonitorTestTXM) Close() error { return nil }

type stubBalanceMonitor struct {
	evmmonitor.BalanceMonitor
	start  func(context.Context) error
	close  func() error
	onHead func(context.Context, *evmtypes.Head)
}

func (m *stubBalanceMonitor) Start(ctx context.Context) error { return m.start(ctx) }

func (m *stubBalanceMonitor) OnNewLongestChain(ctx context.Context, head *evmtypes.Head) {
	if m.onHead != nil {
		m.onHead(ctx, head)
	}
}

func (m *stubBalanceMonitor) Close() error {
	if m.close != nil {
		return m.close()
	}
	return nil
}

func balanceMonitorTestTOMLConfig(t *testing.T) *evmtoml.EVMConfig {
	t.Helper()
	cfg, err := evmconfig.BuildChainlinkEVMTOML(Info{
		ChainID: "1337",
		Nodes:   []Node{{HTTPUrl: "http://127.0.0.1:1"}},
	})
	require.NoError(t, err)
	return cfg
}

func newBalanceMonitorTestChain(t *testing.T) *standaloneChain {
	t.Helper()
	cfg := clevmconfig.NewTOMLChainScopedConfig(balanceMonitorTestTOMLConfig(t))
	headBroadcaster := heads.NewBroadcaster(logger.Test(t))
	require.NoError(t, headBroadcaster.Start(t.Context()))
	chain := &standaloneChain{
		lggr:            logger.Test(t),
		selector:        protocol.ChainSelector(1),
		chainClient:     &balanceMonitorTestClient{calls: make(chan common.Address, 2)},
		chainConfig:     cfg,
		headBroadcaster: headBroadcaster,
		txm:             &balanceMonitorTestTXM{},
		txmKeyName:      testBalanceMonitorKeyName,
		chainKeystore: &keystest.FakeChainStore{
			Addresses: keystest.Addresses{testBalanceMonitorAddress},
		},
		fromAddresses: []common.Address{testBalanceMonitorAddress},
		recoveryStop:  make(services.StopChan),
	}
	t.Cleanup(func() { assert.NoError(t, chain.Close()) })
	return chain
}

func TestStandaloneBalanceMonitorReadsTransmitterOnStartupAndNewHeads(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	rpcClient := &balanceMonitorTestClient{calls: make(chan common.Address, 2)}
	rpcClient.balance.Store(100)
	chain.chainClient = rpcClient

	// The production builder receives the same restricted store that TXM uses.
	chain.mu.Lock()
	chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
	chain.mu.Unlock()
	requireBalanceMonitorCall(t, rpcClient, testBalanceMonitorAddress)
	require.Eventually(t, func() bool {
		balance := chain.balanceMonitor.GetEthBalance(testBalanceMonitorAddress)
		return balance != nil && balance.ToInt().Int64() == 100
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	rpcClient.balance.Store(150)
	chain.headBroadcaster.BroadcastNewLongestChain(&evmtypes.Head{Number: 1})
	requireBalanceMonitorCall(t, rpcClient, testBalanceMonitorAddress)
	require.Eventually(t, func() bool {
		balance := chain.balanceMonitor.GetEthBalance(testBalanceMonitorAddress)
		return balance != nil && balance.ToInt().Int64() == 150
	}, tests.WaitTimeout(t), 10*time.Millisecond)
}

func TestStandaloneBalanceMonitorRealRebuildsAndLeavesNoGoroutines(t *testing.T) {
	// Not parallel: goleak checks the whole process after each real monitor has closed.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for range 2 {
		chain := newBalanceMonitorTestChain(t)
		rpcClient := &balanceMonitorTestClient{calls: make(chan common.Address, 2)}
		rpcClient.balance.Store(100)
		chain.chainClient = rpcClient
		chain.mu.Lock()
		chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
		chain.mu.Unlock()
		requireBalanceMonitorCall(t, rpcClient, testBalanceMonitorAddress)
		require.NoError(t, chain.Close())
	}
}

func TestNewContractTransmitterStartsBalanceMonitorInBackground(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	started := make(chan struct{})
	closed := make(chan struct{})
	monitor := &stubBalanceMonitor{
		start: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			// Native upstream Start reports RPC and keystore failures only through logs and returns nil.
			return nil
		},
		close: func() error {
			close(closed)
			return nil
		},
	}
	chain.newBalanceMonitor = func(_ client.Client, addresses evmkeys.AddressLister, _ logger.Logger, tokenAddress *common.Address) (evmmonitor.BalanceMonitor, error) {
		require.Same(t, chain.chainKeystore, addresses)
		require.Nil(t, tokenAddress)
		return monitor, nil
	}

	transmitter, err := chain.NewContractTransmitter(
		t.Context(), protocol.ChainSelector(1), nil, testBalanceMonitorKeyName, common.HexToAddress("0x1"),
	)
	require.NoError(t, err)
	require.NotNil(t, transmitter)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("balance monitor did not start")
	}

	// Close cancels the delayed startup before stopping the head broadcaster and client.
	require.NoError(t, chain.Close())
	select {
	case <-closed:
	default:
		t.Fatal("balance monitor was not closed")
	}
	require.NoError(t, chain.Degraded(), "shutdown cancellation is not a monitor failure")
	require.Nil(t, chain.unsubscribeBalanceMonitor, "a canceled start must not publish a late head subscription")
}

func TestStandaloneBalanceMonitorReplaysCurrentHeadAfterStart(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	started := make(chan struct{})
	releaseStart := make(chan struct{})
	headReceived := make(chan *evmtypes.Head, 1)
	monitor := &stubBalanceMonitor{
		start: func(context.Context) error {
			close(started)
			<-releaseStart
			return nil
		},
		onHead: func(_ context.Context, head *evmtypes.Head) { headReceived <- head },
	}
	chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
		return monitor, nil
	}
	chain.mu.Lock()
	chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
	chain.mu.Unlock()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("balance monitor did not start")
	}

	// Deliver a head while Start is blocked: it must not reach the monitor until startup succeeds.
	headObserved := make(chan struct{})
	observer := &stubBalanceMonitor{onHead: func(context.Context, *evmtypes.Head) { close(headObserved) }}
	_, unsubscribe := chain.headBroadcaster.Subscribe(observer)
	defer unsubscribe()
	head := &evmtypes.Head{Number: 42}
	chain.headBroadcaster.BroadcastNewLongestChain(head)
	select {
	case <-headObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("head broadcaster did not process the test head")
	}
	select {
	case <-headReceived:
		t.Fatal("monitor received a head before Start succeeded")
	default:
	}

	close(releaseStart)
	chain.balanceMonitorStartWG.Wait()
	select {
	case got := <-headReceived:
		require.Same(t, head, got)
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not receive the current head after startup")
	}
}

func TestStandaloneBalanceMonitorCloseWaitsForBuilder(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	builderStarted := make(chan struct{})
	releaseBuilder := make(chan struct{})
	var closeCalls atomic.Int64
	monitor := &stubBalanceMonitor{
		// Once built, native upstream Start logs canceled initial reads and returns nil.
		start: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		close: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
		close(builderStarted)
		<-releaseBuilder
		return monitor, nil
	}
	chain.mu.Lock()
	chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
	chain.mu.Unlock()
	select {
	case <-builderStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("balance monitor builder did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- chain.Close() }()
	require.Never(t, func() bool {
		select {
		case <-closed:
			return true
		default:
			return false
		}
	}, 100*time.Millisecond, 10*time.Millisecond, "Close returned while the builder was still running")
	close(releaseBuilder)
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after releasing the builder")
	}
	require.Equal(t, int64(1), closeCalls.Load())
	require.Nil(t, chain.unsubscribeBalanceMonitor, "a start completed during Close must not subscribe")
}

func TestBalanceMonitorFailureDoesNotDisableContractTransmitter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		startErr error
		buildErr error
	}{
		{name: "construction failure", buildErr: errors.New("metric registration failed")},
		{name: "start failure", startErr: errors.New("service start failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := newBalanceMonitorTestChain(t)
			var closed atomic.Bool
			if tc.buildErr != nil {
				chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
					return nil, tc.buildErr
				}
			} else {
				chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
					return &stubBalanceMonitor{
						start: func(context.Context) error { return tc.startErr },
						close: func() error {
							closed.Store(true)
							return errors.New("cannot be stopped from this state")
						},
					}, nil
				}
			}
			monitorErr := tc.buildErr
			if monitorErr == nil {
				monitorErr = tc.startErr
			}

			transmitter, err := chain.NewContractTransmitter(
				t.Context(), protocol.ChainSelector(1), nil, testBalanceMonitorKeyName, common.HexToAddress("0x1"),
			)
			require.NoError(t, err)
			require.NotNil(t, transmitter)
			chain.balanceMonitorStartWG.Wait()

			require.ErrorContains(t, chain.Degraded(), "balance monitor")
			require.ErrorIs(t, chain.Degraded(), monitorErr)
			accessor := &accessor{runtime: chain}
			require.ErrorIs(t, accessor.Degraded(), monitorErr, "executor health includes the runtime monitor failure")
			require.Nil(t, chain.unsubscribeBalanceMonitor, "a failed start must never subscribe to heads")
			require.NoError(t, chain.Close())
			require.False(t, closed.Load(), "a failed monitor must not be closed from its StartFailed state")
		})
	}
}

func TestStandaloneBalanceMonitorHonorsDisabledSetting(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	cfg := balanceMonitorTestTOMLConfig(t)
	cfg.BalanceMonitor.Enabled = new(false)
	chain.chainConfig = clevmconfig.NewTOMLChainScopedConfig(cfg)

	called := false
	chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
		called = true
		return nil, errors.New("must not construct a disabled monitor")
	}
	chain.mu.Lock()
	chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
	chain.mu.Unlock()
	require.False(t, called)
	require.Nil(t, chain.balanceMonitor)
	require.NoError(t, chain.Degraded())
}

func TestStandaloneBalanceMonitorERC20CachesDecimalsAndClosesCleanly(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	cfg := balanceMonitorTestTOMLConfig(t)
	token := evmtypes.EIP55AddressFromAddress(common.HexToAddress("0x2"))
	cfg.BalanceMonitor.ERC20TokenAddress = &token
	chain.chainConfig = clevmconfig.NewTOMLChainScopedConfig(cfg)

	var decimalsCalls, balanceCalls atomic.Int64
	rpcClient := &balanceMonitorTestClient{calls: make(chan common.Address, 2)}
	rpcClient.callContract = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		if msg.To == nil {
			return nil, errors.New("contract call has no destination")
		}
		switch {
		case bytes.Equal(msg.Data, balanceMonitorERC20ABI.Methods["decimals"].ID):
			if *msg.To != token.Address() {
				return nil, errors.New("wrong ERC-20 token decimals destination")
			}
			decimalsCalls.Add(1)
			return balanceMonitorERC20ABI.Methods["decimals"].Outputs.Pack(uint8(6))
		case len(msg.Data) >= 4 && bytes.Equal(msg.Data[:4], balanceMonitorERC20ABI.Methods["balanceOf"].ID):
			if *msg.To != token.Address() {
				return nil, errors.New("wrong ERC-20 token balance destination")
			}
			balanceCalls.Add(1)
			return balanceMonitorERC20ABI.Methods["balanceOf"].Outputs.Pack(big.NewInt(12345))
		default:
			return nil, errors.New("unexpected contract method")
		}
	}
	chain.chainClient = rpcClient
	chain.mu.Lock()
	chain.startBalanceMonitorLocked(context.Background(), chain.chainKeystore)
	chain.mu.Unlock()

	require.Eventually(t, func() bool {
		chain.mu.Lock()
		monitor := chain.balanceMonitor
		started := chain.balanceMonitorStarted
		chain.mu.Unlock()
		return started && monitor != nil && monitor.GetEthBalance(testBalanceMonitorAddress) != nil
	}, tests.WaitTimeout(t), 10*time.Millisecond)
	chain.balanceMonitorStartWG.Wait()
	require.NoError(t, chain.Degraded())
	require.NoError(t, chain.Close())
	// Any second decimals lookup made by upstream Start must be served from the cache.
	require.Equal(t, int64(1), decimalsCalls.Load())
	balance := chain.balanceMonitor.GetEthBalance(testBalanceMonitorAddress)
	require.NotNil(t, balance)
	require.Equal(t, "12345000000000000", balance.ToInt().String(), "6-decimal token balances scale to 18-decimal units")
	require.Equal(t, int64(1), balanceCalls.Load())
}

func TestStandaloneBalanceMonitorERC20FailedPreflightConstructsNothing(t *testing.T) {
	chain := newBalanceMonitorTestChain(t)
	cfg := balanceMonitorTestTOMLConfig(t)
	token := evmtypes.EIP55AddressFromAddress(common.HexToAddress("0x2"))
	cfg.BalanceMonitor.ERC20TokenAddress = &token
	chain.chainConfig = clevmconfig.NewTOMLChainScopedConfig(cfg)

	rpcClient := &balanceMonitorTestClient{calls: make(chan common.Address, 2)}
	rpcClient.callContract = func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
		return nil, errors.New("decimals unavailable")
	}
	chain.chainClient = rpcClient
	called := false
	chain.newBalanceMonitor = func(client.Client, evmkeys.AddressLister, logger.Logger, *common.Address) (evmmonitor.BalanceMonitor, error) {
		called = true
		return nil, errors.New("must not construct after failed preflight")
	}
	transmitter, err := chain.NewContractTransmitter(
		t.Context(), protocol.ChainSelector(1), nil, testBalanceMonitorKeyName, common.HexToAddress("0x1"),
	)
	require.NoError(t, err)
	require.NotNil(t, transmitter)
	chain.balanceMonitorStartWG.Wait()

	require.False(t, called)
	require.ErrorContains(t, chain.Degraded(), "failed to initialize ERC-20 token decimals")
	require.ErrorContains(t, chain.Degraded(), "decimals unavailable")
	require.Nil(t, chain.balanceMonitor)
	require.Nil(t, chain.unsubscribeBalanceMonitor)
	require.NoError(t, chain.Close())
}

func requireBalanceMonitorCall(t *testing.T, client *balanceMonitorTestClient, address common.Address) {
	t.Helper()
	select {
	case got := <-client.calls:
		require.Equal(t, address, got)
	case <-time.After(5 * time.Second):
		t.Fatal("balance monitor did not query the transmitter")
	}
}
