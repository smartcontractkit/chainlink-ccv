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
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/rpc"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
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
	src        evm.Chain
	dest       evm.Chain
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
	c, ok := m.impl.(*ccvEvm.CCIP17EVM)
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
			ccvEvm.DefaultReceiverQualifier))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find mock receiver address in datastore: %w", err).Error(), Failed: true}
	}
	committeeVerifierProxyRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcChain.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverProxyType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			ccvEvm.DefaultCommitteeVerifierQualifier))
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
		}(seqNo, m.sentTimes[seqNo])
	}
	return &wasp.Response{Data: "ok"}
}

func assertMessagesAsync(tc TestingContext, gun *EVMTXGun) func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
	fromSelector := gun.src.Selector
	toSelector := gun.dest.Selector

	metricsChan := make(chan metrics.MessageMetrics, 100)
	var wg sync.WaitGroup
	var totalSent, totalReachedVerifier, totalVerified, totalAggregated, totalIndexed, totalReachedExecutor, totalSentToChainInExecutor, totalReceived int
	var countMu sync.Mutex

	// Track specific messages for detailed reporting
	sentMessages := make(map[uint64]string)
	reachedVerifierMessages := make(map[uint64]string)
	verifiedMessages := make(map[uint64]string)
	aggregatedMessages := make(map[uint64]string)
	indexedMessages := make(map[uint64]string)
	reachedExecutorMessages := make(map[uint64]string)
	sentToChainInExecutorMessages := make(map[uint64]string)
	receivedMessages := make(map[uint64]string)

	// Create a context with timeout for verification
	verifyCtx, cancelVerify := context.WithTimeout(tc.Ctx, tc.Timeout)

	go func() {
		defer close(metricsChan)
		defer cancelVerify()

		for sentMsg := range gun.sentMsgCh {
			msgIDHex := common.BytesToHash(sentMsg.MessageID[:]).Hex()
			countMu.Lock()
			totalSent++
			sentMessages[sentMsg.SeqNo] = msgIDHex
			countMu.Unlock()

			// Launch a goroutine for each message to verify it
			wg.Add(1)
			go func(msg SentMessage) {
				defer wg.Done()

				msgIDHex := common.BytesToHash(msg.MessageID[:]).Hex()

				result, err := tc.AssertMessage(msg.MessageID, AssertMessageOptions{
					TickInterval:            2 * time.Second,
					Timeout:                 1 * time.Minute,
					ExpectedVerifierResults: 1,
					AssertVerifierLogs:      true,
					AssertExecutorLogs:      true,
				})

				countMu.Lock()
				if result.VerifierReached {
					totalReachedVerifier++
					reachedVerifierMessages[msg.SeqNo] = msgIDHex
				}
				if result.VerifierSigned {
					totalVerified++
					verifiedMessages[msg.SeqNo] = msgIDHex
				}
				if result.AggregatorFound {
					totalAggregated++
					aggregatedMessages[msg.SeqNo] = msgIDHex
				}
				if result.IndexerFound {
					totalIndexed++
					indexedMessages[msg.SeqNo] = msgIDHex
				}
				if result.ExecutorLogFound {
					totalReachedExecutor++
					reachedExecutorMessages[msg.SeqNo] = msgIDHex
				}
				if result.SentToChainFound {
					totalSentToChainInExecutor++
					sentToChainInExecutorMessages[msg.SeqNo] = msgIDHex
				}
				countMu.Unlock()

				if err != nil {
					tc.T.Logf("Message %d (ID: %s) verification failed: %v", msg.SeqNo, msgIDHex, err)
					return
				}

				tc.T.Logf("Message %d verified - aggregator entries, indexer: %d verifications",
					msg.SeqNo,
					len(result.IndexedVerifications.VerifierResults))

				execEvent, err := tc.Impl.WaitOneExecEventBySeqNo(verifyCtx, fromSelector, toSelector, msg.SeqNo, tc.Timeout)

				if verifyCtx.Err() != nil {
					tc.T.Logf("Message %d verification timed out", msg.SeqNo)
					return
				}

				if err != nil {
					tc.T.Logf("Failed to get execution event for sequence number %d: %v", msg.SeqNo, err)
					return
				}

				if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
					tc.T.Logf("Message with sequence number %d was not successfully executed, state: %d", msg.SeqNo, execEvent.State)
					return
				}

				executedTime := time.Now()
				latency := executedTime.Sub(msg.SentTime)

				tc.T.Logf("Message with sequence number %d successfully executed (latency: %v)", msg.SeqNo, latency)

				countMu.Lock()
				totalReceived++
				receivedMessages[msg.SeqNo] = msgIDHex
				countMu.Unlock()

				metricsChan <- metrics.MessageMetrics{
					SeqNo:           msg.SeqNo,
					MessageID:       msgIDHex,
					SentTime:        msg.SentTime,
					ExecutedTime:    executedTime,
					LatencyDuration: latency,
				}
			}(sentMsg)
		}

		tc.T.Logf("All messages sent, waiting for assertion to complete")

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			tc.T.Logf("All verification goroutines completed")
		case <-verifyCtx.Done():
			tc.T.Logf("Verification timeout reached, some goroutines may still be running")
		}
	}()

	return func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
		datum := make([]metrics.MessageMetrics, 0, 100)
		for metric := range metricsChan {
			datum = append(datum, metric)
		}

		countMu.Lock()
		totals := metrics.MessageTotals{
			Sent:                          totalSent,
			ReachedVerifier:               totalReachedVerifier,
			Verified:                      totalVerified,
			Aggregated:                    totalAggregated,
			Indexed:                       totalIndexed,
			ReachedExecutor:               totalReachedExecutor,
			SentToChainInExecutor:         totalSentToChainInExecutor,
			Received:                      totalReceived,
			SentMessages:                  sentMessages,
			ReachedVerifierMessages:       reachedVerifierMessages,
			VerifiedMessages:              verifiedMessages,
			AggregatedMessages:            aggregatedMessages,
			IndexedMessages:               indexedMessages,
			ReachedExecutorMessages:       reachedExecutorMessages,
			SentToChainInExecutorMessages: sentToChainInExecutorMessages,
			ReceivedMessages:              receivedMessages,
		}
		countMu.Unlock()

		notVerified := totals.Sent - totals.Received
		tc.T.Logf("Verification complete - Sent: %d, ReachedVerifier: %d, Verified: %d, Aggregated: %d, Indexed: %d, ReachedExecutor: %d, SentToChain: %d, Received: %d, Not Received: %d",
			totals.Sent, totals.ReachedVerifier, totals.Verified, totals.Aggregated, totals.Indexed, totals.ReachedExecutor, totals.SentToChainInExecutor, totals.Received, notVerified)

		return datum, totals
	}
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

	indexerURL := fmt.Sprintf("http://127.0.0.1:%d", in.Indexer.Port)
	defaultAggregatorAddr := fmt.Sprintf("127.0.0.1:%d", defaultAggregatorPort(in))

	defaultAggregatorClient, err := ccv.NewAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		defaultAggregatorAddr)
	require.NoError(t, err)
	require.NotNil(t, defaultAggregatorClient)
	t.Cleanup(func() {
		defaultAggregatorClient.Close()
	})

	indexerClient := ccv.NewIndexerClient(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerURL)
	require.NotNil(t, indexerClient)

	t.Run("clean", func(t *testing.T) {
		// just a clean load test to measure performance
		rps := int64(5)
		testDuration := 30 * time.Second

		tc := NewTestingContext(t, ctx, impl, defaultAggregatorClient, indexerClient)
		tc.Timeout = 5 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)
		waitForMetrics := assertMessagesAsync(tc, gun)

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

		require.Equal(t, summary.TotalSent, summary.TotalAggregated)
		require.Equal(t, summary.TotalSent, summary.TotalIndexed)
		require.LessOrEqual(t, summary.P90VerifierToExecutor, 30*time.Second)
	})

	t.Run("rpc latency", func(t *testing.T) {
		// 400ms latency for any RPC node
		_, err = chaos.ExecPumba("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=150s delay --time=400 re2:blockchain-node-.*", 0*time.Second)
		require.NoError(t, err)

		rps := int64(1)
		testDuration := 120 * time.Second

		tc := NewTestingContext(t, ctx, impl, defaultAggregatorClient, indexerClient)
		tc.Timeout = 220 * time.Second

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)
		waitForMetrics := assertMessagesAsync(tc, gun)

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
	})

	t.Run("gas", func(t *testing.T) {
		rps := int64(1)
		testDuration := 5 * time.Minute

		tc := NewTestingContext(t, ctx, impl, defaultAggregatorClient, indexerClient)
		tc.Timeout = 10 * time.Minute

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)
		waitForMetrics := assertMessagesAsync(tc, gun)

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
		rps := int64(1)
		testDuration := 5 * time.Minute

		tc := NewTestingContext(t, ctx, impl, defaultAggregatorClient, indexerClient)

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)
		waitForMetrics := assertMessagesAsync(tc, gun)

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

		tc := NewTestingContext(t, ctx, impl, defaultAggregatorClient, indexerClient)

		p, gun := createLoadProfile(in, rps, testDuration, e, selectors, impl, srcChain, dstChain)
		waitForMetrics := assertMessagesAsync(tc, gun)

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
