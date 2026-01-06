package e2e

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// VerifierController manages stopping and starting verifier containers.
type VerifierController struct {
	dockerClient *client.Client
	logger       zerolog.Logger
	verifiers    []string // Container names of verifiers
}

// NewVerifierController creates a new verifier controller.
func NewVerifierController(ctx context.Context, verifierNames []string, logger zerolog.Logger) (*VerifierController, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &VerifierController{
		dockerClient: dockerClient,
		logger:       logger,
		verifiers:    verifierNames,
	}, nil
}

// StopVerifiers stops all verifier containers.
func (vc *VerifierController) StopVerifiers(ctx context.Context) error {
	vc.logger.Info().Strs("verifiers", vc.verifiers).Msg("Stopping verifiers")
	for _, verifierName := range vc.verifiers {
		containers, err := vc.dockerClient.ContainerList(ctx, container.ListOptions{
			All:     true,
			Filters: filters.NewArgs(filters.Arg("name", verifierName)),
		})
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		for _, c := range containers {
			timeout := 10
			stopOptions := container.StopOptions{
				Timeout: &timeout,
			}
			if err := vc.dockerClient.ContainerStop(ctx, c.ID, stopOptions); err != nil {
				vc.logger.Warn().Str("container", c.ID).Err(err).Msg("Failed to stop container")
				continue
			}
			vc.logger.Info().Str("container", verifierName).Str("id", c.ID[:12]).Msg("Stopped verifier")
		}
	}
	return nil
}

// StartVerifiers starts all verifier containers.
func (vc *VerifierController) StartVerifiers(ctx context.Context) error {
	vc.logger.Info().Strs("verifiers", vc.verifiers).Msg("Starting verifiers")
	for _, verifierName := range vc.verifiers {
		containers, err := vc.dockerClient.ContainerList(ctx, container.ListOptions{
			All:     true,
			Filters: filters.NewArgs(filters.Arg("name", verifierName)),
		})
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		for _, c := range containers {
			if err := vc.dockerClient.ContainerStart(ctx, c.ID, container.StartOptions{}); err != nil {
				vc.logger.Warn().Str("container", c.ID).Err(err).Msg("Failed to start container")
				continue
			}
			vc.logger.Info().Str("container", verifierName).Str("id", c.ID[:12]).Msg("Started verifier")
		}
	}
	return nil
}

// Close closes the docker client.
func (vc *VerifierController) Close() error {
	return vc.dockerClient.Close()
}

// TestThroughputWithVerifierRestart tests throughput by:
// 1. Stopping verifiers
// 2. Sending 10k messages
// 3. Restarting verifiers
// 4. Tracking execution times.
func TestThroughputWithVerifierRestart(t *testing.T) {
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

	// Collect verifier container names from config
	verifierNames := make([]string, 0, len(in.Verifier))
	for _, ver := range in.Verifier {
		if ver.Mode == "standalone" && ver.ContainerName != "" {
			verifierNames = append(verifierNames, ver.ContainerName)
		}
	}
	require.NotEmpty(t, verifierNames, "No standalone verifiers found in config")

	// Create verifier controller
	verifierController, err := NewVerifierController(ctx, verifierNames, *l)
	require.NoError(t, err)
	t.Cleanup(func() {
		verifierController.Close()
	})

	// Ensure we have at least 1 WETH and approve router to spend it
	ensureWETHBalanceAndApproval(ctx, t, *l, e, srcChain, big.NewInt(requiredWETHBalance))

	tc := NewTestingContext(t, ctx, chainImpls, defaultAggregatorClient, indexerClient)
	tc.Timeout = 1 * time.Minute // Extended timeout for 10k messages

	// Step 1: Stop verifiers
	t.Log("Step 1: Stopping verifiers")
	err = verifierController.StopVerifiers(ctx)
	require.NoError(t, err)

	// Wait a bit to ensure verifiers are fully stopped
	time.Sleep(10 * time.Second)

	// Step 2: Send 10k messages
	t.Log("Step 2: Sending 10k messages")
	const totalMessages = 10000
	const rps = int64(60) // High RPS to send messages quickly
	testDuration := max(time.Duration(totalMessages/rps)*time.Second, 10*time.Second)

	loadSelectors := []uint64{srcChain.Selector, dstChain.Selector}
	p, gun := createLoadProfile(in, rps, testDuration, e, loadSelectors, chainImpls, srcChain, dstChain)
	gun.setShouldEmit(false)

	// Track when we start sending messages
	sendStartTime := time.Now()
	t.Logf("Starting to send %d messages at %d RPS", totalMessages, rps)

	_, err = p.Run(true)
	require.NoError(t, err)

	sendEndTime := time.Now()
	t.Logf("Finished sending messages. Duration: %v", sendEndTime.Sub(sendStartTime))

	// Step 3: Restart verifiers
	t.Log("Step 3: Restarting verifiers")
	restartStartTime := time.Now()
	err = verifierController.StartVerifiers(ctx)
	require.NoError(t, err)

	// Wait for verifiers to be ready (they should start processing messages)
	time.Sleep(3 * time.Second)
	restartEndTime := time.Now()
	t.Logf("Verifiers restarted. Restart duration: %v", restartEndTime.Sub(restartStartTime))

	// Step 4: Wait for all messages to be executed and collect metrics
	t.Log("Step 4: Waiting for all messages to be executed")

	// Get all sent sequence numbers from the gun
	gun.seqNosMu.Lock()
	sentSeqNos := make([]uint64, len(gun.sentSeqNos))
	copy(sentSeqNos, gun.sentSeqNos)
	sentTimesCopy := make(map[uint64]time.Time)
	for k, v := range gun.sentTimes {
		sentTimesCopy[k] = v
	}
	gun.seqNosMu.Unlock()

	t.Logf("Tracking execution for %d messages", len(sentSeqNos))
	require.Greater(t, len(sentSeqNos), 0, "Should have sent at least one message")

	// Create context for verification with extended timeout
	verifyCtx, cancelVerify := context.WithTimeout(ctx, tc.Timeout)
	defer cancelVerify()

	// Track execution metrics
	type executionResult struct {
		seqNo        uint64
		executedTime time.Time
		success      bool
		err          error
	}

	resultsChan := make(chan executionResult, len(sentSeqNos))
	var wg sync.WaitGroup

	fromSelector := srcChain.Selector
	toSelector := dstChain.Selector

	// Check each message individually
	for _, seqNo := range sentSeqNos {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()

			// Wait for execution event
			execEvent, err := tc.Impl[dstChain.Selector].WaitOneExecEventBySeqNo(verifyCtx, fromSelector, toSelector, seq, tc.Timeout)
			// Handle error case
			if err != nil {
				select {
				case resultsChan <- executionResult{
					seqNo:   seq,
					success: false,
					err:     err,
				}:
				case <-verifyCtx.Done():
					// Context canceled, don't send
				}
				return
			}

			// Handle non-success state
			if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
				select {
				case resultsChan <- executionResult{
					seqNo:   seq,
					success: false,
					err:     fmt.Errorf("execution state not success: %d", execEvent.State),
				}:
				case <-verifyCtx.Done():
					// Context canceled, don't send
				}
				return
			}

			// Success case - always send result
			executedTime := time.Now()
			select {
			case resultsChan <- executionResult{
				seqNo:        seq,
				executedTime: executedTime,
				success:      true,
			}:
			case <-verifyCtx.Done():
				// Context canceled, don't send
			}
		}(seqNo)
	}

	// Wait for all verifications to complete
	// We need to wait for all goroutines to finish before closing the channel
	// to prevent "send on closed channel" panic
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for all goroutines to complete or timeout
	select {
	case <-done:
		t.Log("All verification goroutines completed")
	case <-verifyCtx.Done():
		t.Log("Verification timeout reached, waiting for goroutines to finish sending")
		// Wait for goroutines to finish, but with a reasonable timeout
		select {
		case <-done:
			t.Log("All goroutines finished after timeout")
		case <-time.After(10 * time.Second):
			t.Log("Timeout waiting for goroutines")
		}
	}

	// Ensure all goroutines have finished before closing channel
	// This is critical to prevent "send on closed channel" panic
	// Call wg.Wait() directly to ensure completion
	wg.Wait()

	// Close channel only after all goroutines have finished
	// This prevents "send on closed channel" panic
	close(resultsChan)

	var executionResults []executionResult

	// Drain results channel
	for result := range resultsChan {
		executionResults = append(executionResults, result)
	}

	// Process results and calculate metrics
	var successfulExecutions []metrics.MessageMetrics
	var failedExecutions []uint64
	var firstExecutionTime time.Time
	var lastExecutionTime time.Time

	for _, result := range executionResults {
		if result.success {
			totalLatency := result.executedTime.Sub(sentTimesCopy[result.seqNo])

			if firstExecutionTime.IsZero() || result.executedTime.Before(firstExecutionTime) {
				firstExecutionTime = result.executedTime
			}
			if lastExecutionTime.IsZero() || result.executedTime.After(lastExecutionTime) {
				lastExecutionTime = result.executedTime
			}

			successfulExecutions = append(successfulExecutions, metrics.MessageMetrics{
				SeqNo:           result.seqNo,
				SentTime:        sentTimesCopy[result.seqNo],
				ExecutedTime:    result.executedTime,
				LatencyDuration: totalLatency,
			})
		} else {
			failedExecutions = append(failedExecutions, result.seqNo)
			t.Logf("Message %d failed to execute: %v", result.seqNo, result.err)
		}
	}

	// Calculate execution times from restart
	executionTimesFromRestart := make([]time.Duration, 0, len(successfulExecutions))
	for _, m := range successfulExecutions {
		execTimeFromRestart := m.ExecutedTime.Sub(restartStartTime)
		executionTimesFromRestart = append(executionTimesFromRestart, execTimeFromRestart)
	}

	// Calculate percentiles for execution time from restart
	var minExecTime, maxExecTime, p90ExecTime, p95ExecTime, p99ExecTime time.Duration
	if len(executionTimesFromRestart) > 0 {
		// Sort execution times
		slices.Sort(executionTimesFromRestart)

		minExecTime = executionTimesFromRestart[0]
		maxExecTime = executionTimesFromRestart[len(executionTimesFromRestart)-1]

		p90Idx := int(float64(len(executionTimesFromRestart)) * 0.90)
		p95Idx := int(float64(len(executionTimesFromRestart)) * 0.95)
		p99Idx := int(float64(len(executionTimesFromRestart)) * 0.99)

		if p90Idx >= len(executionTimesFromRestart) {
			p90Idx = len(executionTimesFromRestart) - 1
		}
		if p95Idx >= len(executionTimesFromRestart) {
			p95Idx = len(executionTimesFromRestart) - 1
		}
		if p99Idx >= len(executionTimesFromRestart) {
			p99Idx = len(executionTimesFromRestart) - 1
		}

		p90ExecTime = executionTimesFromRestart[p90Idx]
		p95ExecTime = executionTimesFromRestart[p95Idx]
		p99ExecTime = executionTimesFromRestart[p99Idx]
	}

	totalExecutionDuration := time.Duration(0)
	if !lastExecutionTime.IsZero() && !restartStartTime.IsZero() {
		totalExecutionDuration = lastExecutionTime.Sub(restartStartTime)
	}

	successRate := 0.0
	if len(sentSeqNos) > 0 {
		successRate = float64(len(successfulExecutions)) / float64(len(sentSeqNos)) * 100
	}

	throughputExecuted := 0.0
	if totalExecutionDuration > 0 {
		throughputExecuted = float64(len(successfulExecutions)) / totalExecutionDuration.Seconds()
	}

	// Print comprehensive summary
	t.Logf("\n"+
		"========================================\n"+
		"      Throughput Test Summary         \n"+
		"========================================\n"+
		"Total Messages Sent:        %d\n"+
		"Total Messages Executed:    %d\n"+
		"Failed Executions:          %d\n"+
		"Success Rate:              %.2f%%\n"+
		"----------------------------------------\n"+
		"Timing:\n"+
		"  Send Start:              %v\n"+
		"  Send End:                %v\n"+
		"  Send Duration:           %v\n"+
		"  Verifier Restart Start:   %v\n"+
		"  Verifier Restart End:     %v\n"+
		"  Restart Duration:        %v\n"+
		"  First Execution:         %v\n"+
		"  Last Execution:          %v\n"+
		"  Total Execution Time:     %v\n"+
		"    (from restart to last)\n"+
		"----------------------------------------\n"+
		"Execution Time from Restart:\n"+
		"  Min:           %v\n"+
		"  Max:           %v\n"+
		"  P90:           %v\n"+
		"  P95:           %v\n"+
		"  P99:           %v\n"+
		"----------------------------------------\n"+
		"Throughput:\n"+
		"  Messages/sec (sent):     %.2f\n"+
		"  Messages/sec (executed): %.2f\n"+
		"========================================\n",
		len(sentSeqNos),
		len(successfulExecutions),
		len(failedExecutions),
		successRate,
		sendStartTime,
		sendEndTime,
		sendEndTime.Sub(sendStartTime),
		restartStartTime,
		restartEndTime,
		restartEndTime.Sub(restartStartTime),
		firstExecutionTime,
		lastExecutionTime,
		totalExecutionDuration,
		minExecTime,
		maxExecTime,
		p90ExecTime,
		p95ExecTime,
		p99ExecTime,
		float64(len(sentSeqNos))/sendEndTime.Sub(sendStartTime).Seconds(),
		throughputExecuted,
	)

	// Assertions
	require.Equal(t, len(sentSeqNos), len(successfulExecutions), "All messages should be executed")
	require.Greater(t, len(sentSeqNos), 0, "Should have sent messages")
}
