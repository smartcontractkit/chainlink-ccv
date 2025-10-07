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
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
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

// MessageMetrics tracks timing information for a single message
type MessageMetrics struct {
	SeqNo           uint64
	SentTime        time.Time
	ExecutedTime    time.Time
	LatencyDuration time.Duration
}

// MetricsSummary holds aggregate metrics for all messages
type MetricsSummary struct {
	TotalMessages int
	MinLatency    time.Duration
	MaxLatency    time.Duration
	P90Latency    time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration
}

type EVMTXGun struct {
	cfg        *ccv.Cfg
	e          *deployment.Environment
	selectors  []uint64
	impl       ccv.CCIP17ProductConfiguration
	src        evm.Chain
	dest       evm.Chain
	sentSeqNos []uint64
	sentTimes  map[uint64]time.Time
	seqNosMu   sync.Mutex
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impl ccv.CCIP17ProductConfiguration, s, d evm.Chain) *EVMTXGun {
	return &EVMTXGun{
		cfg:        cfg,
		e:          e,
		selectors:  selectors,
		impl:       impl,
		src:        s,
		dest:       d,
		sentSeqNos: make([]uint64, 0),
		sentTimes:  make(map[uint64]time.Time),
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
		}
	}

	err = m.impl.SendArgsV3Message(ctx, m.e, m.cfg.CLDF.Addresses, m.selectors, srcChain.ChainSelector, dstChain.ChainSelector, uint16(1), "0x68B1D87F95878fE05B998F19b66F4baba5De1aed", "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c", nil, nil,
		[]protocol.CCV{
			{
				CCVAddress: common.HexToAddress("0x0B306BF915C4d645ff596e518fAf3F9669b97016").Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		[]protocol.CCV{}, 0)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}
	return &wasp.Response{Data: "ok"}
}

// verifyAllMessagesExecuted checks that all messages tracked by the gun were successfully executed
// and collects timing metrics for each message
func verifyAllMessagesExecuted(t *testing.T, ctx context.Context, gun *EVMTXGun, impl *ccvEvm.CCIP17EVM, timeout time.Duration) []MessageMetrics {
	gun.seqNosMu.Lock()
	seqNos := make([]uint64, len(gun.sentSeqNos))
	copy(seqNos, gun.sentSeqNos)
	sentTimes := make(map[uint64]time.Time)
	for k, v := range gun.sentTimes {
		sentTimes[k] = v
	}
	gun.seqNosMu.Unlock()

	fromSelector := gun.src.Selector
	toSelector := gun.dest.Selector

	t.Logf("Verifying %d messages were executed from selector %d to %d", len(seqNos), fromSelector, toSelector)

	metrics := make([]MessageMetrics, 0, len(seqNos))

	for _, seqNo := range seqNos {
		execEvent, err := impl.WaitOneExecEventBySeqNo(ctx, fromSelector, toSelector, seqNo, timeout)
		require.NoError(t, err, "Failed to get execution event for sequence number %d", seqNo)
		require.NotNil(t, execEvent)

		// State 2 indicates successful execution
		event := execEvent.(*ccvAggregator.CCVAggregatorExecutionStateChanged)
		state := event.State
		require.Equal(t, uint8(2), state, "Message with sequence number %d was not successfully executed, state: %d", seqNo, state)

		t.Logf("Message with sequence number %d successfully executed", seqNo)
		// Record execution time and calculate latency
		executedTime := time.Now()
		sentTime, ok := sentTimes[seqNo]
		if ok {
			latency := executedTime.Sub(sentTime)
			metrics = append(metrics, MessageMetrics{
				SeqNo:           seqNo,
				SentTime:        sentTime,
				ExecutedTime:    executedTime,
				LatencyDuration: latency,
			})
		}
	}

	t.Logf("Successfully verified all %d messages were executed", len(seqNos))
	return metrics
}

// calculateMetricsSummary computes aggregate statistics from message metrics
func calculateMetricsSummary(metrics []MessageMetrics) MetricsSummary {
	if len(metrics) == 0 {
		return MetricsSummary{}
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

	return MetricsSummary{
		TotalMessages: len(metrics),
		MinLatency:    latencies[0],
		MaxLatency:    latencies[len(latencies)-1],
		P90Latency:    latencies[p90Index],
		P95Latency:    latencies[p95Index],
		P99Latency:    latencies[p99Index],
	}
}

// printMetricsSummary outputs message timing metrics in a readable format
func printMetricsSummary(t *testing.T, summary MetricsSummary) {
	t.Logf("\n"+
		"========================================\n"+
		"         Message Timing Metrics        \n"+
		"========================================\n"+
		"Total Messages:  %d\n"+
		"Min Latency:     %v\n"+
		"Max Latency:     %v\n"+
		"P90 Latency:     %v\n"+
		"P95 Latency:     %v\n"+
		"P99 Latency:     %v\n"+
		"========================================",
		summary.TotalMessages,
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

func createLoadProfile(in *ccv.Cfg, rps int64, testDuration time.Duration, e *deployment.Environment, selectors []uint64, impl ccv.CCIP17ProductConfiguration, s, d evm.Chain) (*wasp.Profile, *EVMTXGun) {
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

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains)
	require.NoError(t, err)
	chains := e.BlockChains.EVMChains()
	require.NotNil(t, chains)
	srcChain := chains[selectors[0]]
	dstChain := chains[selectors[1]]
	b := ccv.NewDefaultCLDFBundle(e)
	e.OperationsBundle = b

	ctx := context.Background()
	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	impl, err := ccvEvm.NewCCIP17EVM(ctx, in.CLDF.Addresses, chainIDs, wsURLs)
	require.NoError(t, err)

	t.Run("clean", func(t *testing.T) {
		// just a clean load test to measure performance
		p, gun := createLoadProfile(in, 5, 30*time.Second, e, selectors, impl, srcChain, dstChain)
		_, err = p.Run(true)
		require.NoError(t, err)
		// verify all messages were executed and collect metrics
		metrics := verifyAllMessagesExecuted(t, ctx, gun, impl, 5*time.Minute)
		summary := calculateMetricsSummary(metrics)
		printMetricsSummary(t, summary)
		// assert any metrics you need
		checkCPUMem(t, in, time.Now())
	})

	t.Run("rpc latency", func(t *testing.T) {
		// 400ms latency for any RPC node
		_, err = chaos.ExecPumba("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=5m delay --time=400 re2:blockchain-node-.*", 0*time.Second)
		require.NoError(t, err)
		p, gun := createLoadProfile(in, 1, 5*time.Second, e, selectors, impl, srcChain, dstChain)
		_, err = p.Run(true)
		require.NoError(t, err)
		// verify all messages were executed and collect metrics
		metrics := verifyAllMessagesExecuted(t, ctx, gun, impl, 5*time.Minute)
		summary := calculateMetricsSummary(metrics)
		printMetricsSummary(t, summary)
	})

	t.Run("gas", func(t *testing.T) {
		// test slow and fast gas spikes on both chains
		p, gun := createLoadProfile(in, 1, 5*time.Minute, e, selectors, impl, srcChain, dstChain)
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
		// verify all messages were executed and collect metrics
		metrics := verifyAllMessagesExecuted(t, ctx, gun, impl, 5*time.Minute)
		summary := calculateMetricsSummary(metrics)
		printMetricsSummary(t, summary)
	})

	t.Run("reorgs", func(t *testing.T) {
		p, gun := createLoadProfile(in, 1, 5*time.Minute, e, selectors, impl, srcChain, dstChain)
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
		// verify all messages were executed and collect metrics
		metrics := verifyAllMessagesExecuted(t, ctx, gun, impl, 5*time.Minute)
		summary := calculateMetricsSummary(metrics)
		printMetricsSummary(t, summary)
	})

	t.Run("services_chaos", func(t *testing.T) {
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
		p, gun := createLoadProfile(in, 1, 5*time.Minute, e, selectors, impl, srcChain, dstChain)
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
		// verify all messages were executed and collect metrics
		metrics := verifyAllMessagesExecuted(t, ctx, gun, impl, 5*time.Minute)
		summary := calculateMetricsSummary(metrics)
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
