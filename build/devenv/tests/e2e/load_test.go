package e2e

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

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

type EVMTXGun struct {
	cfg  *ccv.Cfg
	e    *deployment.Environment
	src  evm.Chain
	dest evm.Chain
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, s, d evm.Chain) *EVMTXGun {
	return &EVMTXGun{
		cfg:  cfg,
		e:    e,
		src:  s,
		dest: d,
	}
}

// Call implements example gun call, assertions on response bodies should be done here.
func (m *EVMTXGun) Call(_ *wasp.Generator) *wasp.Response {
	b := ccv.NewDefaultCLDFBundle(m.e)
	m.e.OperationsBundle = b

	routerAddr := ccv.MustGetContractAddressForSelector(m.cfg, m.src.Selector, router.ContractType)

	argsV3, err := ccv.NewV3ExtraArgs(1, common.Address{}, []byte{}, []byte{}, []types.CCV{}, []types.CCV{}, 0)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: m.dest.Selector,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(m.src.DeployerKey.From.Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsV3,
		},
	}

	feeReport, err := operations.ExecuteOperation(b, router.GetFee, m.src, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: m.src.Selector,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	ccipSendArgs.Value = feeReport.Output
	sendReport, err := operations.ExecuteOperation(b, router.CCIPSend, m.src, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: m.src.Selector,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}
	if !sendReport.Output.Executed {
		return &wasp.Response{Error: "CLDF operation was not executed", Failed: true}
	}
	ccv.Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", m.dest.Selector).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")
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

func createLoadProfile(in *ccv.Cfg, rps int64, testDuration time.Duration, e *deployment.Environment, s, d evm.Chain) *wasp.Profile {
	return wasp.NewProfile().
		Add(wasp.NewGenerator(&wasp.Config{
			LoadType: wasp.RPS,
			GenName:  "src-dst-single-token",
			Schedule: wasp.Combine(
				wasp.Plain(rps, testDuration),
			),
			Gun: NewEVMTransactionGun(in, e, s, d),
			Labels: map[string]string{
				"go_test_name": "load-clean-src",
				"branch":       "test",
				"commit":       "test",
			},
			LokiConfig: wasp.NewEnvLokiConfig(),
		}))
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

	t.Run("clean", func(t *testing.T) {
		// just a clean load test to measure performance
		_, err = createLoadProfile(in, 5, 30*time.Second, e, srcChain, dstChain).Run(true)
		require.NoError(t, err)
		// assert any metrics you need
		checkCPUMem(t, in, time.Now())
	})

	t.Run("rpc latency", func(t *testing.T) {
		// 400ms latency for any RPC node
		_, err = chaos.ExecPumba("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=5m delay --time=400 re2:blockchain-node-.*", 0*time.Second)
		require.NoError(t, err)
		_, err = createLoadProfile(in, 1, 5*time.Minute, e, srcChain, dstChain).Run(true)
		require.NoError(t, err)
	})

	t.Run("gas", func(t *testing.T) {
		// test slow and fast gas spikes on both chains
		p := createLoadProfile(in, 1, 5*time.Minute, e, srcChain, dstChain)
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
	})

	t.Run("reorgs", func(t *testing.T) {
		p := createLoadProfile(in, 1, 5*time.Minute, e, srcChain, dstChain)
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
		p := createLoadProfile(in, 1, 5*time.Minute, e, srcChain, dstChain)
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
