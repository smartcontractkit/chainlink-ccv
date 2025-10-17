package e2e

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	f "github.com/smartcontractkit/chainlink-testing-framework/framework"
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

// MessageMetrics tracks timing information for a single message.
type MessageMetrics struct {
	SeqNo           uint64
	SentTime        time.Time
	ExecutedTime    time.Time
	LatencyDuration time.Duration
}

// MetricsSummary holds aggregate metrics for all messages.
type MetricsSummary struct {
	TotalSent     int
	TotalVerified int
	MinLatency    time.Duration
	MaxLatency    time.Duration
	P90Latency    time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration
}

// SentMessage represents a message that was sent and needs verification.
type SentMessage struct {
	SeqNo    uint64
	SentTime time.Time
}

type EVMTXGun struct {
	cfg        *ccv.Cfg
	e          *deployment.Environment
	selectors  []uint64
	impl       cciptestinterfaces.CCIP17ProductConfiguration
	src        evm.Chain
	dest       evm.Chain
	sentSeqNos []uint64
	sentTimes  map[uint64]time.Time
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

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impl cciptestinterfaces.CCIP17ProductConfiguration, s, d evm.Chain) *EVMTXGun {
	return &EVMTXGun{
		cfg:        cfg,
		e:          e,
		selectors:  selectors,
		impl:       impl,
		src:        s,
		dest:       d,
		sentSeqNos: make([]uint64, 0),
		sentTimes:  make(map[uint64]time.Time),
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
	c, ok := m.impl.(*ccvEvm.CCIP17EVM)
	if ok {
		seqNo, err := c.GetExpectedNextSequenceNumber(ctx, srcChain.ChainSelector, dstChain.ChainSelector)
		if err == nil {
			sentTime := time.Now()
			m.seqNosMu.Lock()
			m.sentSeqNos = append(m.sentSeqNos, seqNo)
			m.sentTimes[seqNo] = sentTime
			m.seqNosMu.Unlock()

			// Push to channel for async verification
			m.sentMsgCh <- SentMessage{
				SeqNo:    seqNo,
				SentTime: sentTime,
			}
		}
	}

	err = m.impl.SendMessage(ctx, srcChain.ChainSelector, dstChain.ChainSelector, cciptestinterfaces.MessageFields{
		Receiver: protocol.UnknownAddress(common.HexToAddress("0x3Aa5ebB10DC797CAC828524e59A333d0A371443c").Bytes()),
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:        3,
		FinalityConfig: uint16(1),
		MandatoryCCVs: []protocol.CCV{
			{
				CCVAddress: common.HexToAddress("0x0B306BF915C4d645ff596e518fAf3F9669b97016").Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		OptionalThreshold: 0,
	})
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}
	return &wasp.Response{Data: "ok"}
}

// verifyMessagesAsync starts async verification of messages as they are sent via channel
// Returns a function that blocks until all messages are verified (or timeout) and returns metrics and counts
// The gun.sentMsgCh channel must be closed (via gun.CloseSentChannel()) when all messages have been sent.
func verifyMessagesAsync(t *testing.T, ctx context.Context, gun *EVMTXGun, impl *ccvEvm.CCIP17EVM, timeout time.Duration) func() ([]MessageMetrics, int, int) {
	fromSelector := gun.src.Selector
	toSelector := gun.dest.Selector

	metricsChan := make(chan MessageMetrics, 100)
	var wg sync.WaitGroup
	var totalSent, totalVerified int
	var countMu sync.Mutex

	// Create a context with timeout for verification
	verifyCtx, cancelVerify := context.WithTimeout(ctx, timeout)

	// Start verification goroutine that reads from the sent messages channel
	go func() {
		defer close(metricsChan)
		defer cancelVerify()

		// Read from channel until it's closed
		for sentMsg := range gun.sentMsgCh {
			countMu.Lock()
			totalSent++
			countMu.Unlock()

			// Launch a goroutine for each message to verify it
			wg.Add(1)
			go func(msg SentMessage) {
				defer wg.Done()

				// Wait for the execution event with context
				execEvent, err := impl.WaitOneExecEventBySeqNo(verifyCtx, fromSelector, toSelector, msg.SeqNo, timeout)

				if verifyCtx.Err() != nil {
					// Context canceled or timed out
					t.Logf("Message %d verification timed out", msg.SeqNo)
					return
				}

				if err != nil {
					t.Logf("Failed to get execution event for sequence number %d: %v", msg.SeqNo, err)
					return
				}

				if execEvent == nil {
					t.Logf("Execution event is nil for sequence number %d", msg.SeqNo)
					return
				}

				// Check execution state
				event := execEvent.(*offramp.OffRampExecutionStateChanged)
				if event.State != uint8(2) {
					t.Logf("Message with sequence number %d was not successfully executed, state: %d", msg.SeqNo, event.State)
					return
				}

				// Calculate latency
				executedTime := time.Now()
				latency := executedTime.Sub(msg.SentTime)

				t.Logf("Message with sequence number %d successfully executed (latency: %v)", msg.SeqNo, latency)

				countMu.Lock()
				totalVerified++
				countMu.Unlock()

				// Send metrics
				metricsChan <- MessageMetrics{
					SeqNo:           msg.SeqNo,
					SentTime:        msg.SentTime,
					ExecutedTime:    executedTime,
					LatencyDuration: latency,
				}
			}(sentMsg)
		}

		// Channel is closed, wait for all verification goroutines to complete or timeout
		t.Logf("All messages received, waiting for verification to complete")

		// Wait for either all goroutines to finish or context timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			t.Logf("All verification goroutines completed")
		case <-verifyCtx.Done():
			t.Logf("Verification timeout reached, some goroutines may still be running")
		}
	}()

	// Return function that collects metrics and counts
	return func() ([]MessageMetrics, int, int) {
		metrics := make([]MessageMetrics, 0, 100)
		for metric := range metricsChan {
			metrics = append(metrics, metric)
		}

		countMu.Lock()
		sent := totalSent
		verified := totalVerified
		countMu.Unlock()

		notVerified := sent - verified
		t.Logf("Verification complete - Sent: %d, Verified: %d, Not Verified: %d",
			sent, verified, notVerified)

		return metrics, sent, verified
	}
}

// calculateMetricsSummary computes aggregate statistics from message metrics.
func calculateMetricsSummary(metrics []MessageMetrics, totalSent, totalVerified int) MetricsSummary {
	summary := MetricsSummary{
		TotalSent:     totalSent,
		TotalVerified: totalVerified,
	}

	if len(metrics) == 0 {
		return summary
	}

	// Extract and sort latencies
	latencies := make([]time.Duration, len(metrics))
	for i, m := range metrics {
		latencies[i] = m.LatencyDuration
	}
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	// Calculate percentiles
	p90Index := int(float64(len(latencies)) * 0.90)
	p95Index := int(float64(len(latencies)) * 0.95)
	p99Index := int(float64(len(latencies)) * 0.99)

	// Handle edge cases for small sample sizes
	if p90Index >= len(latencies) {
		p90Index = len(latencies) - 1
	}
	if p95Index >= len(latencies) {
		p95Index = len(latencies) - 1
	}
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}

	summary.MinLatency = latencies[0]
	summary.MaxLatency = latencies[len(latencies)-1]
	summary.P90Latency = latencies[p90Index]
	summary.P95Latency = latencies[p95Index]
	summary.P99Latency = latencies[p99Index]

	return summary
}

// printMetricsSummary outputs message timing metrics in a readable format.
func printMetricsSummary(t *testing.T, summary MetricsSummary) {
	notVerified := summary.TotalSent - summary.TotalVerified
	successRate := 0.0
	if summary.TotalSent > 0 {
		successRate = float64(summary.TotalVerified) / float64(summary.TotalSent) * 100
	}

	t.Logf("\n"+
		"========================================\n"+
		"         Message Timing Metrics        \n"+
		"========================================\n"+
		"Total Sent:      %d\n"+
		"Total Verified:  %d\n"+
		"Not Verified:    %d\n"+
		"Success Rate:    %.2f%%\n"+
		"----------------------------------------\n"+
		"Min Latency:     %v\n"+
		"Max Latency:     %v\n"+
		"P90 Latency:     %v\n"+
		"P95 Latency:     %v\n"+
		"P99 Latency:     %v\n"+
		"========================================",
		summary.TotalSent,
		summary.TotalVerified,
		notVerified,
		successRate,
		summary.MinLatency,
		summary.MaxLatency,
		summary.P90Latency,
		summary.P95Latency,
		summary.P99Latency,
	)
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

func createLoadProfile(in *ccv.Cfg, rps int64, testDuration time.Duration, e *deployment.Environment, selectors []uint64, impl cciptestinterfaces.CCIP17ProductConfiguration, s, d evm.Chain) (*wasp.Profile, *EVMTXGun) {
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
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	if os.Getenv("LOKI_URL") == "" {
		_ = os.Setenv("LOKI_URL", ccv.DefaultLokiURL)
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

	impl, err := ccvEvm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	t.Run("clean", func(t *testing.T) {
		// just a clean load test to measure performance
		rps := int64(5)
		testDuration := 30 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		// Start async verification before running the profile
		waitForMetrics := verifyMessagesAsync(t, ctx, gun, impl, 5*time.Minute)

		_, err = p.Run(true)
		require.NoError(t, err)

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics, totalSent, totalVerified := waitForMetrics()
		summary := calculateMetricsSummary(metrics, totalSent, totalVerified)
		printMetricsSummary(t, summary)

		// assert any metrics you need
		checkCPUMem(t, in, time.Now())
	})

	t.Run("rpc latency", func(t *testing.T) {
		// 400ms latency for any RPC node
		_, err = chaos.ExecPumba("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=45s delay --time=400 re2:blockchain-node-.*", 0*time.Second)
		require.NoError(t, err)

		rps := int64(1)
		testDuration := 30 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		// Start async verification before running the profile
		waitForMetrics := verifyMessagesAsync(t, ctx, gun, impl, 120*time.Second)

		_, err = p.Run(true)
		require.NoError(t, err)

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics, totalSent, totalVerified := waitForMetrics()
		summary := calculateMetricsSummary(metrics, totalSent, totalVerified)
		printMetricsSummary(t, summary)
	})

	t.Run("gas", func(t *testing.T) {
		// test slow and fast gas spikes on both chains
		rps := int64(1)
		testDuration := 5 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		// Start async verification before running the profile
		waitForMetrics := verifyMessagesAsync(t, ctx, gun, impl, 10*time.Minute)

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

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics, totalSent, totalVerified := waitForMetrics()
		summary := calculateMetricsSummary(metrics, totalSent, totalVerified)
		printMetricsSummary(t, summary)
	})

	t.Run("reorgs", func(t *testing.T) {
		rps := int64(1)
		testDuration := 5 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)

		// Start async verification before running the profile
		waitForMetrics := verifyMessagesAsync(t, ctx, gun, impl, 10*time.Minute)

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

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics, totalSent, totalVerified := waitForMetrics()
		summary := calculateMetricsSummary(metrics, totalSent, totalVerified)
		printMetricsSummary(t, summary)
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

		// Start async verification before running the profile
		waitForMetrics := verifyMessagesAsync(t, ctx, gun, impl, 10*time.Minute)

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

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics, totalSent, totalVerified := waitForMetrics()
		summary := calculateMetricsSummary(metrics, totalSent, totalVerified)
		printMetricsSummary(t, summary)
	})
}

// checkLogs is currently unused but kept for future debugging purposes.
// func checkLogs(t *testing.T, in *ccv.Cfg, end time.Time) {
//	logs, err := f.NewLokiQueryClient(f.LocalLokiBaseURL, "", f.BasicAuth{}, f.QueryParams{
//		Query:     "{job=\"ctf\",container=\"don-node1\"}",
//		StartTime: end.Add(-time.Minute),
//		EndTime:   end,
//		Limit:     100,
//	}).QueryRange(context.Background())
//	require.NoError(t, err)
//	fmt.Println(logs)
// }

func checkCPUMem(t *testing.T, in *ccv.Cfg, end time.Time) {
	pc := f.NewPrometheusQueryClient(f.LocalPrometheusBaseURL)
	// no more than 10% CPU for this test
	maxCPU := 10.0
	cpuResp, err := pc.Query("sum(rate(container_cpu_usage_seconds_total{name=~\".*don.*\"}[5m])) by (name) *100", end)
	require.NoError(t, err)
	cpu := f.ToLabelsMap(cpuResp)
	for i := 0; i < in.NodeSets[0].Nodes; i++ {
		nodeLabel := fmt.Sprintf("name:don-node%d", i)
		nodeCpu, err := strconv.ParseFloat(cpu[nodeLabel][0].(string), 64)
		ccv.Plog.Info().Int("Node", i).Float64("CPU", nodeCpu).Msg("CPU usage percentage")
		require.NoError(t, err)
		require.LessOrEqual(t, nodeCpu, maxCPU)
	}
	// no more than 200mb for this test
	maxMem := int(200e6) // 200mb
	memoryResp, err := pc.Query("sum(container_memory_rss{name=~\".*don.*\"}) by (name)", end)
	require.NoError(t, err)
	mem := f.ToLabelsMap(memoryResp)
	for i := 0; i < in.NodeSets[0].Nodes; i++ {
		nodeLabel := fmt.Sprintf("name:don-node%d", i)
		nodeMem, err := strconv.Atoi(mem[nodeLabel][0].(string))
		ccv.Plog.Info().Int("Node", i).Int("Memory", nodeMem).Msg("Total memory")
		require.NoError(t, err)
		require.LessOrEqual(t, nodeMem, maxMem)
	}
}
