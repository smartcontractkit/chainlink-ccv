package e2e

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

type ChaosTestCase struct {
	run      func() error
	validate func() error
	name     string
}

type GasTestCase struct {
	increase         *big.Int
	gasFunc          func(t *testing.T, r *rpc.RPCClient, blockPace time.Duration)
	validate         func() error
	name             string
	chainURL         string
	waitBetweenTests time.Duration
}

// SentMessage represents a message that was sent and needs verification.
type SentMessage struct {
	SeqNo     uint64
	MessageID [32]byte
	SentTime  time.Time
}

type EVMTXGun struct {
	cfg        *ccv.Cfg
	e          *deployment.Environment
	selectors  []uint64
	impl       cciptestinterfaces.CCIP17ProductConfiguration
	src        cldfevm.Chain
	dest       cldfevm.Chain
	sentSeqNos []uint64
	sentTimes  map[uint64]time.Time
	msgIDs     map[uint64][32]byte
	seqNosMu   sync.Mutex
	sentMsgCh  chan SentMessage // Channel for real-time message notifications
	closeOnce  sync.Once        // Ensure channel is closed only once
}

// CloseSentChannel closes the sent messages channel to signal no more messages will be sent.
func (m *EVMTXGun) CloseSentChannel() {
	m.closeOnce.Do(func() {
		close(m.sentMsgCh)
	})
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impl cciptestinterfaces.CCIP17ProductConfiguration, s, d cldfevm.Chain) *EVMTXGun {
	return &EVMTXGun{
		cfg:        cfg,
		e:          e,
		selectors:  selectors,
		impl:       impl,
		src:        s,
		dest:       d,
		sentSeqNos: make([]uint64, 0),
		sentTimes:  make(map[uint64]time.Time),
		msgIDs:     make(map[uint64][32]byte),
		sentMsgCh:  make(chan SentMessage, 1000), // Buffered channel to avoid blocking
	}
}

// Call implements example gun call, assertions on response bodies should be done here.
func (m *EVMTXGun) Call(_ *wasp.Generator) *wasp.Response {
	b := ccv.NewDefaultCLDFBundle(m.e)
	m.e.OperationsBundle = b
	ctx := context.Background()

	chainIDs := make([]string, 0)
	for _, bc := range m.cfg.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
	}

	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[0], chainsel.FamilyEVM)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[1], chainsel.FamilyEVM)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	// Get sequence number before sending and record timestamp
	c, ok := m.impl.(*evm.CCIP17EVM)
	var seqNo uint64
	if ok {
		seqNo, err = c.GetExpectedNextSequenceNumber(ctx, srcChain.ChainSelector, dstChain.ChainSelector)
		if err == nil {
			sentTime := time.Now()
			m.seqNosMu.Lock()
			m.sentSeqNos = append(m.sentSeqNos, seqNo)
			m.sentTimes[seqNo] = sentTime
			m.seqNosMu.Unlock()
		}
	}

	mockReceiverRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			dstChain.ChainSelector,
			datastore.ContractType(mock_receiver.ContractType),
			semver.MustParse(mock_receiver.Deploy.Version()),
			evm.DefaultReceiverQualifier))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find mock receiver address in datastore: %w", err).Error(), Failed: true}
	}
	committeeVerifierProxyRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcChain.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverProxyType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			evm.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find committee verifier proxy address in datastore: %w", err).Error(), Failed: true}
	}
	_, err = m.impl.SendMessage(ctx, srcChain.ChainSelector, dstChain.ChainSelector, cciptestinterfaces.MessageFields{
		Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()),
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:        3,
		FinalityConfig: uint16(1),
		CCVs: []protocol.CCV{
			{
				CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	})
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to send message: %w", err).Error(), Failed: true}
	}

	// After sending, resolve MessageID via the on-chain Sent event and push enriched message into channel
	if ok {
		m.seqNosMu.Lock()
		sentAt := m.sentTimes[seqNo]
		m.seqNosMu.Unlock()
		go func(localSeq uint64, sentAt time.Time) {
			// Wait up to 2 minutes for the Sent event
			sentEvent, waitErr := c.WaitOneSentEventBySeqNo(ctx, srcChain.ChainSelector, dstChain.ChainSelector, localSeq, 2*time.Minute)
			if waitErr != nil {
				return
			}
			m.seqNosMu.Lock()
			m.msgIDs[localSeq] = sentEvent.MessageID
			m.seqNosMu.Unlock()
			m.sentMsgCh <- SentMessage{SeqNo: localSeq, MessageID: sentEvent.MessageID, SentTime: sentAt}
		}(seqNo, sentAt)
	}
	return &wasp.Response{Data: "ok"}
}

func gasControlFunc(t *testing.T, r *rpc.RPCClient, blockPace time.Duration) {
	startGasPrice := big.NewInt(2e9)
	// ramp
	for i := 0; i < 10; i++ {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		err = r.AnvilSetNextBlockBaseFeePerGas(startGasPrice)
		require.NoError(t, err)
		startGasPrice = startGasPrice.Add(startGasPrice, big.NewInt(1e9))
		time.Sleep(blockPace)
	}
	// hold
	for i := 0; i < 10; i++ {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		time.Sleep(blockPace)
		err = r.AnvilSetNextBlockBaseFeePerGas(startGasPrice)
		require.NoError(t, err)
	}
	// release
	for i := 0; i < 10; i++ {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		time.Sleep(blockPace)
	}
}

func createLoadProfile(in *ccv.Cfg, rps int64, testDuration time.Duration, e *deployment.Environment, selectors []uint64, impl cciptestinterfaces.CCIP17ProductConfiguration, s, d cldfevm.Chain) (*wasp.Profile, *EVMTXGun) {
	gun := NewEVMTransactionGun(in, e, selectors, impl, s, d)
	profile := wasp.NewProfile().
		Add(wasp.NewGenerator(&wasp.Config{
			LoadType: wasp.RPS,
			GenName:  "src-dst-single-token",
			Schedule: wasp.Combine(
				wasp.Plain(rps, testDuration),
			),
			Gun: gun,
			Labels: map[string]string{
				"go_test_name": "load-clean-src",
				"branch":       "test",
				"commit":       "test",
			},
			LokiConfig: wasp.NewEnvLokiConfig(),
		}))
	return profile, gun
}

func TestE2ELoad(t *testing.T) {
	outfile := os.Getenv("LOAD_TEST_OUT_FILE")
	if outfile == "" {
		outfile = "../../env-out.toml"
	}
	in, err := ccv.LoadOutput[ccv.Cfg](outfile)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})
	if os.Getenv("LOKI_URL") == "" {
		_ = os.Setenv("LOKI_URL", ccv.DefaultLokiURL)
	}
	if os.Getenv("PROM_URL") == "" {
		_ = os.Setenv("PROM_URL", ccv.DefaultPromURL)
	}
	srcRPCURL := in.Blockchains[0].Out.Nodes[0].ExternalHTTPUrl
	dstRPCURL := in.Blockchains[1].Out.Nodes[0].ExternalHTTPUrl

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	chains := e.BlockChains.EVMChains()
	require.NotNil(t, chains)
	srcChain := chains[selectors[0]]
	dstChain := chains[selectors[1]]
	b := ccv.NewDefaultCLDFBundle(e)
	e.OperationsBundle = b

	ctx := ccv.Plog.WithContext(context.Background())
	l := zerolog.Ctx(ctx)
	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	impl, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	// Initialize Prometheus helper
	promHelper, err := NewPrometheusHelper(os.Getenv("PROM_URL"), *zerolog.Ctx(ctx))
	require.NoError(t, err)
	t.Run("clean", func(t *testing.T) {
		rps := int64(1)
		testDuration := 30 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(true)
		require.NoError(t, err)
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 5*time.Second)
	})

	t.Run("burst", func(t *testing.T) {
		rps := int64(5)
		testDuration := 30 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(true)
		require.NoError(t, err)
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 5*time.Second)
	})

	t.Run("rpc latency", func(t *testing.T) {
		testDuration := 1 * time.Hour
		expectedP90Latency := 5 * time.Second
		timeoutDuration := time.Duration((testDuration.Seconds()+expectedP90Latency.Seconds())*10) * time.Second
		// 400ms latency for any RPC node
		pumbaCmd := fmt.Sprintf("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=%s delay --time=400 re2:blockchain-.*", timeoutDuration)
		_, err = chaos.ExecPumba(pumbaCmd, 0*time.Second)
		require.NoError(t, err)

		rps := int64(1)

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(true)
		require.NoError(t, err)
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 5*time.Second)
	})

	t.Run("gas", func(t *testing.T) {
		rps := int64(1)
		testDuration := 5 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(false)
		require.NoError(t, err)

		waitBetweenTests := 30 * time.Second

		tcs := []GasTestCase{
			{
				name:             "Slow spike src",
				chainURL:         srcRPCURL,
				waitBetweenTests: waitBetweenTests,
				increase:         big.NewInt(1e9),
				gasFunc:          gasControlFunc,
				validate:         func() error { return nil },
			},
			{
				name:             "Fast spike src",
				chainURL:         srcRPCURL,
				waitBetweenTests: waitBetweenTests,
				increase:         big.NewInt(5e9),
				gasFunc:          gasControlFunc,
				validate:         func() error { return nil },
			},
			{
				name:             "Slow spike dst",
				chainURL:         dstRPCURL,
				waitBetweenTests: waitBetweenTests,
				increase:         big.NewInt(1e9),
				gasFunc:          gasControlFunc,
				validate:         func() error { return nil },
			},
			{
				name:             "Fast spike dst",
				chainURL:         dstRPCURL,
				waitBetweenTests: waitBetweenTests,
				increase:         big.NewInt(5e9),
				gasFunc:          gasControlFunc,
				validate:         func() error { return nil },
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Log(tc.name)
				r := rpc.New(tc.chainURL, nil)
				tc.gasFunc(t, r, 1*time.Second)
				err = tc.validate()
				require.NoError(t, err)
				time.Sleep(tc.waitBetweenTests)
			})
		}
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 10*time.Second)
	})

	t.Run("reorgs", func(t *testing.T) {
		rps := int64(1)
		testDuration := 5 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(false)
		require.NoError(t, err)

		tcs := []struct {
			validate   func() error
			name       string
			chainURL   string
			wait       time.Duration
			reorgDepth int
		}{
			{
				name:       "Reorg src with depth: 1",
				wait:       30 * time.Second,
				chainURL:   srcRPCURL,
				reorgDepth: 1,
				validate: func() error {
					// add clients and validate
					return nil
				},
			},
			{
				name:       "Reorg dst with depth: 1",
				wait:       30 * time.Second,
				chainURL:   dstRPCURL,
				reorgDepth: 1,
				validate: func() error {
					return nil
				},
			},
			{
				name:       "Reorg src with depth: 5",
				wait:       30 * time.Second,
				chainURL:   srcRPCURL,
				reorgDepth: 5,
				validate: func() error {
					return nil
				},
			},
			{
				name:       "Reorg dst with depth: 5",
				wait:       30 * time.Second,
				chainURL:   dstRPCURL,
				reorgDepth: 5,
				validate: func() error {
					return nil
				},
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				r := rpc.New(tc.chainURL, nil)
				err := r.GethSetHead(tc.reorgDepth)
				require.NoError(t, err)
				time.Sleep(tc.wait)
				err = tc.validate()
				require.NoError(t, err)
			})
		}
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 10*time.Second)
	})

	t.Run("services_chaos", func(t *testing.T) {
		rps := int64(1)
		testDuration := 5 * time.Minute

		tcs := []ChaosTestCase{
			{
				name: "Reboot a single node",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:don-node1",
						30*time.Second,
					)
					return nil
				},
				validate: func() error { return nil },
			},
			{
				name: "Reboot two nodes",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:don-node1",
						0*time.Second,
					)
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:don-node2",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
			{
				name: "One slow CL node",
				run: func() error {
					_, err = chaos.ExecPumba(
						"netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=1m delay --time=1000 re2:don-node1",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
			{
				name: "Stop the indexer",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:indexer",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
			{
				name: "Stop the aggregator",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:aggregator",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
			{
				name: "Stop the verifier",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:verifier",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
			{
				name: "Stop the executor",
				run: func() error {
					_, err = chaos.ExecPumba(
						"stop --duration=20s --restart re2:executor",
						30*time.Second,
					)
					return err
				},
				validate: func() error { return nil },
			},
		}

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		_, err = p.Run(false)
		require.NoError(t, err)

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				t.Log(tc.name)
				err = tc.run()
				require.NoError(t, err)
				err = tc.validate()
				require.NoError(t, err)
			})
		}
		p.Wait()

		waitForAllMessagesToBeExecuted(t, ctx, promHelper, len(gun.msgIDs))
		assertP90LatencyBelowThreshold(t, ctx, promHelper, 10*time.Second)
	})
}

// This is not perfect there are case where we could reprocess message and the metric would reach the expected value
// but for load test is not completed yet. It is also not going to work unless we create a new environment for each test.
func waitForAllMessagesToBeExecuted(t *testing.T, ctx context.Context, promHelper *PrometheusHelper, totalMessageExpected int) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		totalMessageProcessed, err := promHelper.GetCurrentCounter(ctx, "executor_message_e2e_duration_seconds_count")
		require.NoError(collect, err)
		t.Logf("Progess: %d/%d", totalMessageProcessed, totalMessageExpected)
		require.GreaterOrEqual(collect, totalMessageProcessed, totalMessageExpected,
			"Total processed messages should be at least total sent messages")
	}, 2*time.Minute, 10*time.Second)
}

func assertP90LatencyBelowThreshold(t *testing.T, ctx context.Context, promHelper *PrometheusHelper, threshold time.Duration) {
	p90E2ELatency, err := promHelper.GetPercentile(ctx, "executor_message_e2e_duration_seconds_bucket", 0.90)
	require.NoError(t, err)
	require.Less(t, p90E2ELatency, threshold.Seconds(),
		fmt.Sprintf("P90 of executor_message_e2e_duration_seconds should be less than %.2f seconds", threshold.Seconds()))
}
