package e2e

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/load"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/weth9"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

const (
	postTestVerificationDelay = 30 * time.Second
	requiredWETHBalance       = 1e18
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

func assertMessagesAsync(tc TestingContext, gun *EVMTXGun, overallTimeout time.Duration) func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
	var wg sync.WaitGroup
	var totalSent, totalReceived atomic.Int32

	sentMessages := &sync.Map{}
	receivedMessages := &sync.Map{}
	metricsData := &sync.Map{}

	verifyCtx, cancelVerify := context.WithTimeout(tc.Ctx, overallTimeout)

	go func() {
		defer cancelVerify()

		for sentMsg := range gun.sentMsgCh {
			select {
			case <-verifyCtx.Done():
				tc.T.Logf("Overall verification timeout reached, stopping new verifications")
				return
			default:
			}

			msgIDHex := common.BytesToHash(sentMsg.MessageID[:]).Hex()
			totalSent.Add(1)
			sentMessages.Store(sentMsg.SeqNo, msgIDHex)

			wg.Add(1)
			go func(msg SentMessage) {
				defer wg.Done()

				msgIDHex := common.BytesToHash(msg.MessageID[:]).Hex()

				if _, ok := tc.Impl[msg.ChainPair.Dest]; !ok {
					tc.T.Logf("No implementation available to verify message %d", msg.SeqNo)
					return
				}

				execEvent, err := tc.Impl[msg.ChainPair.Dest].WaitOneExecEventBySeqNo(verifyCtx, msg.ChainPair.Src, msg.SeqNo, 0)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						tc.T.Logf("Message %d verification cancelled or timed out", msg.SeqNo)
					} else {
						tc.T.Logf("Failed to get execution event for sequence number %d: %v", msg.SeqNo, err)
					}
					return
				}

				if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
					tc.T.Logf("Message with sequence number %d was not successfully executed, state: %d", msg.SeqNo, execEvent.State)
					return
				}

				executedTime := time.Now()
				latency := executedTime.Sub(msg.SentTime)

				tc.T.Logf("Message with sequence number %d successfully executed (latency: %v)", msg.SeqNo, latency)

				totalReceived.Add(1)
				receivedMessages.Store(msg.SeqNo, msgIDHex)

				metricsData.Store(msg.SeqNo, metrics.MessageMetrics{
					SeqNo:           msg.SeqNo,
					MessageID:       msgIDHex,
					SourceChain:     msg.ChainPair.Src,
					DestChain:       msg.ChainPair.Dest,
					SentTime:        msg.SentTime,
					ExecutedTime:    executedTime,
					LatencyDuration: latency,
				})
			}(sentMsg)
		}

		tc.T.Logf("All messages sent, waiting for verifications to complete")

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			tc.T.Logf("All verification goroutines completed successfully")
		case <-verifyCtx.Done():
			tc.T.Logf("Verification timeout reached, %d messages may be unverified", totalSent.Load()-totalReceived.Load())
		}
	}()

	return func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
		<-verifyCtx.Done()

		datum := make([]metrics.MessageMetrics, 0, int(totalReceived.Load()))
		metricsData.Range(func(key, value any) bool {
			datum = append(datum, value.(metrics.MessageMetrics))
			return true
		})

		sent := make(map[uint64]string)
		sentMessages.Range(func(key, value any) bool {
			sent[key.(uint64)] = value.(string)
			return true
		})

		received := make(map[uint64]string)
		receivedMessages.Range(func(key, value any) bool {
			received[key.(uint64)] = value.(string)
			return true
		})

		totals := metrics.MessageTotals{
			Sent:             int(totalSent.Load()),
			Received:         int(totalReceived.Load()),
			SentMessages:     sent,
			ReceivedMessages: received,
		}

		notVerified := totals.Sent - totals.Received
		tc.T.Logf("Verification complete - Sent: %d, ReachedVerifier: %d, Verified: %d, Aggregated: %d, Indexed: %d, ReachedExecutor: %d, SentToChain: %d, Received: %d, Not Received: %d",
			totals.Sent, totals.ReachedVerifier, totals.Verified, totals.Aggregated, totals.Indexed, totals.ReachedExecutor, totals.SentToChainInExecutor, totals.Received, notVerified)

		return datum, totals
	}
}

func ensureWETHBalanceAndApproval(ctx context.Context, t *testing.T, logger zerolog.Logger, e *deployment.Environment, chain cldfevm.Chain, requiredWETH *big.Int) {
	logger.Info().Str("chain", strconv.FormatUint(chain.Selector, 10)).Msg("Ensuring WETH balance and approval")
	wethContract, err := e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			chain.Selector,
			datastore.ContractType(weth.ContractType),
			semver.MustParse(weth.Deploy.Version()),
			""))
	require.NoError(t, err)

	wethInstance, err := weth9.NewWETH9(common.HexToAddress(wethContract.Address), chain.Client)
	require.NoError(t, err)

	routerInstance, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		chain.Selector,
		datastore.ContractType(router.ContractType),
		semver.MustParse(router.Deploy.Version()),
		""))
	require.NoError(t, err)

	for _, user := range chain.Users {
		logger.Info().Str("user address", user.From.String()).Msg("User address")
		balance, err := chain.Client.BalanceAt(ctx, user.From, nil)
		require.NoError(t, err)
		logger.Info().Str("balance", balance.String()).Msg("Deployer balance before deposit")

		wethBalance, err := wethInstance.BalanceOf(nil, user.From)
		require.NoError(t, err)
		logger.Info().Str("wethBalance", wethBalance.String()).Str("requiredWETH", requiredWETH.String()).Msg("Deployer WETH balance before deposit")

		if wethBalance.Cmp(requiredWETH) < 0 {
			depositAmount := new(big.Int).Sub(requiredWETH, wethBalance)
			oldValue := user.Value
			user.Value = depositAmount
			tx1, err := wethInstance.Deposit(user)
			require.NoError(t, err)
			_, err = chain.Confirm(tx1)
			require.NoError(t, err)
			user.Value = oldValue
			logger.Info().Str("depositAmount", depositAmount.String()).Msg("Deposited WETH")
		}

		tx, err := wethInstance.Approve(user, common.HexToAddress(routerInstance.Address), requiredWETH)
		require.NoError(t, err)
		_, err = chain.Confirm(tx)
		require.NoError(t, err)
		logger.Info().Str("approvedAmount", requiredWETH.String()).Msg("Approved WETH for router")
	}
}

func gasControlFunc(t *testing.T, r *rpc.RPCClient, blockPace time.Duration) {
	startGasPrice := big.NewInt(2e9)
	// ramp
	for range 10 {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		err = r.AnvilSetNextBlockBaseFeePerGas(startGasPrice)
		require.NoError(t, err)
		startGasPrice = startGasPrice.Add(startGasPrice, big.NewInt(1e9))
		time.Sleep(blockPace)
	}
	// hold
	for range 10 {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		time.Sleep(blockPace)
		err = r.AnvilSetNextBlockBaseFeePerGas(startGasPrice)
		require.NoError(t, err)
	}
	// release
	for range 10 {
		err := r.PrintBlockBaseFee()
		require.NoError(t, err)
		time.Sleep(blockPace)
	}
}

func createLoadProfile(in *ccv.Cfg, rps int64, testDuration time.Duration, e *deployment.Environment, selectors []uint64, impl map[uint64]cciptestinterfaces.CCIP17, s, d cldfevm.Chain) (*wasp.Profile, *EVMTXGun) {
	gun := NewEVMTransactionGun(in, e, selectors, impl, []uint64{s.Selector}, []uint64{d.Selector})
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
			LokiConfig: nil,
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
	lib, err := ccv.NewLib(l, outfile)
	require.NoError(t, err)
	chainImpls, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	var defaultAggregatorClient *ccv.AggregatorClient
	if _, ok := in.AggregatorEndpoints[evm.DefaultCommitteeVerifierQualifier]; ok {
		defaultAggregatorClient, err = in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
			evm.DefaultCommitteeVerifierQualifier)
		require.NoError(t, err)
		require.NotNil(t, defaultAggregatorClient)
		t.Cleanup(func() {
			defaultAggregatorClient.Close()
		})
	}

	var indexerMonitor *ccv.IndexerMonitor
	indexerClient, err := lib.Indexer()
	if err == nil {
		indexerMonitor, err = ccv.NewIndexerMonitor(
			zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
			indexerClient)
		require.NoError(t, err)
		require.NotNil(t, indexerMonitor)
	}

	// Ensure we have at least 1 WETH and approve router to spend it
	ensureWETHBalanceAndApproval(ctx, t, *l, e, srcChain, big.NewInt(requiredWETHBalance))

	t.Run("clean", func(t *testing.T) {
		// just a clean load test to measure performance
		rps := int64(5)
		testDuration := 30 * time.Second

		tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerMonitor)
		tc.Timeout = 30 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, chainImpls, srcChain, dstChain)
		overallTimeout := testDuration + (2 * tc.Timeout)
		waitForMetrics := assertMessagesAsync(tc, gun, overallTimeout)

		_, err = p.Run(true)
		require.NoError(t, err)

		p.Wait()
		time.Sleep(postTestVerificationDelay)
		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics_datum, totals := waitForMetrics()

		// Enrich metrics with log data collected during test
		tc.enrichMetrics(metrics_datum)

		summary := metrics.CalculateMetricsSummary(metrics_datum, totals)
		metrics.PrintMetricsSummary(t, summary)

		require.Equal(t, summary.TotalSent, summary.TotalReceived)
		require.LessOrEqual(t, summary.P90Latency, 8*time.Second)
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

		tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerMonitor)
		tc.Timeout = timeoutDuration

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, chainImpls, srcChain, dstChain)
		overallTimeout := testDuration + timeoutDuration
		waitForMetrics := assertMessagesAsync(tc, gun, overallTimeout)

		_, err = p.Run(true)
		require.NoError(t, err)

		// Close the channel to signal no more messages will be sent
		gun.CloseSentChannel()

		// Wait for all messages to be verified and collect metrics
		metrics_datum, totals := waitForMetrics()

		// Enrich metrics with log data collected during test
		tc.enrichMetrics(metrics_datum)

		summary := metrics.CalculateMetricsSummary(metrics_datum, totals)
		metrics.PrintMetricsSummary(t, summary)

		require.Equal(t, summary.TotalSent, summary.TotalReceived)
		require.LessOrEqual(t, summary.P90Latency, expectedP90Latency)
	})

	t.Run("gas", func(t *testing.T) {
		srcRPCURL := in.Blockchains[0].Out.Nodes[0].ExternalHTTPUrl
		dstRPCURL := in.Blockchains[1].Out.Nodes[0].ExternalHTTPUrl

		rps := int64(1)
		testDuration := 5 * time.Minute

		tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerMonitor)
		tc.Timeout = 10 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, chainImpls, srcChain, dstChain)
		overallTimeout := testDuration + tc.Timeout
		waitForMetrics := assertMessagesAsync(tc, gun, overallTimeout)

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
		metrics_datum, totals := waitForMetrics()

		// Enrich metrics with log data collected during test
		tc.enrichMetrics(metrics_datum)

		summary := metrics.CalculateMetricsSummary(metrics_datum, totals)
		metrics.PrintMetricsSummary(t, summary)
	})

	t.Run("reorgs", func(t *testing.T) {
		srcRPCURL := in.Blockchains[0].Out.Nodes[0].ExternalHTTPUrl
		dstRPCURL := in.Blockchains[1].Out.Nodes[0].ExternalHTTPUrl

		rps := int64(1)
		testDuration := 5 * time.Minute

		tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerMonitor)

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, chainImpls, srcChain, dstChain)
		overallTimeout := testDuration + (2 * tc.Timeout)
		waitForMetrics := assertMessagesAsync(tc, gun, overallTimeout)

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
		metrics_datum, totals := waitForMetrics()

		// Enrich metrics with log data collected during test
		tc.enrichMetrics(metrics_datum)

		summary := metrics.CalculateMetricsSummary(metrics_datum, totals)
		metrics.PrintMetricsSummary(t, summary)
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

		tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerMonitor)

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, chainImpls, srcChain, dstChain)
		overallTimeout := testDuration + (2 * tc.Timeout)
		waitForMetrics := assertMessagesAsync(tc, gun, overallTimeout)

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
		metrics_datum, totals := waitForMetrics()

		// Enrich metrics with log data collected during test
		tc.enrichMetrics(metrics_datum)

		summary := metrics.CalculateMetricsSummary(metrics_datum, totals)
		metrics.PrintMetricsSummary(t, summary)
	})
}

func TestStaging(t *testing.T) {
	outfile := os.Getenv("LOAD_TEST_OUT_FILE")
	if outfile == "" {
		outfile = "../../env-staging.toml"
	}
	in, err := ccv.LoadOutput[ccv.Cfg](outfile)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	chains := e.BlockChains.EVMChains()
	require.NotNil(t, chains)
	b := ccv.NewDefaultCLDFBundle(e)
	e.OperationsBundle = b

	ctx := ccv.Plog.WithContext(context.Background())
	l := zerolog.Ctx(ctx)
	lib, err := ccv.NewLib(l, outfile)
	require.NoError(t, err)
	chainImpls, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	var defaultAggregatorClient *ccv.AggregatorClient
	if _, ok := in.AggregatorEndpoints[evm.DefaultCommitteeVerifierQualifier]; ok {
		defaultAggregatorClient, err = in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
			evm.DefaultCommitteeVerifierQualifier)
		require.NoError(t, err)
		require.NotNil(t, defaultAggregatorClient)
		t.Cleanup(func() {
			defaultAggregatorClient.Close()
		})
	}

	var indexerClient *ccv.IndexerClient
	if in.IndexerEndpoint != "" {
		indexerClient, err = ccv.NewIndexerClient(
			zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
			in.IndexerEndpoint)
		require.NotNil(t, indexerClient)
		require.NoError(t, err)
	}

	// multi chain mesh load test with config file
	t.Run("multi_chain_load", func(t *testing.T) {
		// Load test config
		testconfigFile := os.Getenv("LOAD_CONFIG_FILE")
		if testconfigFile == "" {
			testconfigFile = "../../staging-load.toml"
		}
		var testConfig *load.TOMLLoadTestRoot
		testConfig, err = load.LoadTestConfigFromTomlFile(testconfigFile)
		if err != nil {
			t.Logf("failed to load test config: %v", err)
			return
		}

		err = verifyTestConfig(e, testConfig)
		require.NoError(t, err)
		testProfile := testConfig.TestProfiles[0]

		var wg sync.WaitGroup
		for _, testProfile := range testConfig.TestProfiles {
			for _, chainInfo := range testProfile.ChainsAsSource {
				wg.Add(1)
				go func(chainInfo load.ChainProfileConfig) {
					defer wg.Done()
					chainSelector, err := strconv.ParseUint(chainInfo.Selector, 10, 64)
					if err != nil {
						t.Logf("failed to parse chain selector: %v", err)
						return
					}
					chain := e.BlockChains.EVMChains()[chainSelector]
					ensureWETHBalanceAndApproval(ctx, t, *l, e, chain, big.NewInt(requiredWETHBalance))
				}(chainInfo)
			}
		}
		wg.Wait()

		messageRate, messageRateDuration := load.ParseMessageRate(testProfile.MessageRate)
		gun := NewEVMTransactionGunFromTestConfig(in, testConfig, e, chainImpls)
		p := wasp.NewProfile().Add(
			wasp.NewGenerator(
				&wasp.Config{
					LoadType:              wasp.RPS,
					GenName:               "multi-chain-mesh-load-test",
					Schedule:              wasp.Plain(messageRate, testProfile.LoadDuration),
					RateLimitUnitDuration: messageRateDuration,
					Gun:                   gun,
					Labels:                map[string]string{"go_test_name": "multi-chain-load"},
					LokiConfig:            nil,
				}),
		)

		_, err = p.Run(true)
		require.NoError(t, err)

		p.Wait()
		time.Sleep(postTestVerificationDelay)
		gun.CloseSentChannel()
		// we don't need to wait for metrics because we can rely on staging metrics
	})
}
