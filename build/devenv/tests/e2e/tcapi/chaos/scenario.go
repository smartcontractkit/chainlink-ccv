package chaos

import (
	"context"
	"fmt"
	"testing"

	"github.com/rs/zerolog"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ScenarioSpec describes a chaos scenario: inject an outage, send a V3 message, assert
// offchain progress, and optionally confirm execution on the destination chain.
type ScenarioSpec struct {
	Lib ccv.Lib
	Src uint64
	Dst uint64

	Fields   cciptestinterfaces.MessageFields
	Opts     cciptestinterfaces.MessageOptions
	SendArgs tcapi.SendArgs

	// Outage, when non-nil, injects a container stop outage and restart.
	Outage *OutageSpec
	// Latency, when non-nil, injects network latency instead of a container stop.
	// Latency takes precedence over Outage when both are set.
	Latency *LatencySpec
	Assert  tcapi.AssertMessageOptions
	Run     tcapi.RunConfig

	// AggregatorQualifier selects which committee aggregator to wait on. Empty uses default.
	AggregatorQualifier string

	// ConfirmExecOnDest waits for successful execution on the destination when true.
	ConfirmExecOnDest bool
	ExpectExecFailure bool
}

// injectChaos injects the chaos fault (latency or outage) from spec and returns
// a cleanup function. Latency takes precedence over Outage when both are set.
func injectChaos(ctx context.Context, spec ScenarioSpec) (func(), error) {
	if spec.Latency != nil {
		cleanup, err := injectLatency(ctx, *spec.Latency)
		if err != nil {
			return nil, fmt.Errorf("inject latency: %w", err)
		}
		return cleanup, nil
	}
	cleanup, err := injectOutage(ctx, spec.Outage)
	if err != nil {
		return nil, fmt.Errorf("inject outage: %w", err)
	}
	return cleanup, nil
}

// RunScenario injects the outage, sends a V3 message, confirms the send on source,
// asserts aggregator/indexer state, and optionally confirms execution on the destination.
// The caller must provide lib and message fields; this package does not filter chains by family.
func RunScenario(t *testing.T, ctx context.Context, spec ScenarioSpec) error {
	v3Src, err := spec.Lib.V3Source(ctx, spec.Src)
	if err != nil {
		return fmt.Errorf("source chain %d does not support V3 message: %w", spec.Src, err)
	}

	v3Dst, err := spec.Lib.V3Destination(ctx, spec.Dst)
	if err != nil {
		return fmt.Errorf("destination chain %d does not support V3 message: %w", spec.Dst, err)
	}

	cleanup, err := injectChaos(ctx, spec)
	if err != nil {
		return err
	}
	t.Cleanup(cleanup)

	sent, _, err := tcapi.SendV3Message(ctx, v3Src, v3Dst, spec.Fields, spec.Opts, spec.SendArgs)
	if err != nil {
		return fmt.Errorf("send v3 message: %w", err)
	}
	if sent.MessageID == (protocol.Bytes32{}) {
		return fmt.Errorf("send returned zero message ID")
	}
	if sent.Message != nil {
		zerolog.Ctx(ctx).Info().Uint64("SeqNo", uint64(sent.Message.SequenceNumber)).Msg("Sent message")
	}

	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sent.MessageID}
	sentTimeout := spec.Run.SentTimeout(tcapi.DefaultSentTimeout)
	execTimeout := spec.Run.ExecTimeout(tcapi.DefaultExecTimeout)
	if spec.Assert.Timeout != 0 {
		execTimeout = spec.Run.ExecTimeout(spec.Assert.Timeout)
		sentTimeout = spec.Assert.Timeout
	}

	if _, err := v3Src.ConfirmSendOnSource(ctx, spec.Dst, messageKey, sentTimeout); err != nil {
		return fmt.Errorf("confirm send on source: %w", err)
	}

	aggregatorClient, indexerMonitor, err := tcapi.SetupOffchainClients(spec.Lib, spec.AggregatorQualifier)
	if err != nil {
		return err
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	assertOpts := spec.Assert
	if assertOpts.Timeout == 0 {
		assertOpts.Timeout = execTimeout
	}

	if assertOpts.TickInterval == 0 {
		assertOpts.TickInterval = tcapi.DefaultSentTimeout / 10
	}

	result, err := testCtx.AssertMessage(sent.MessageID, assertOpts)
	if err != nil {
		return fmt.Errorf("assert message: %w", err)
	}
	if aggregatorClient != nil && result.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}
	if indexerMonitor != nil && len(result.IndexedVerifications.Results) != assertOpts.ExpectedVerifierResults {
		return fmt.Errorf("expected %d indexed verifications, got %d",
			assertOpts.ExpectedVerifierResults, len(result.IndexedVerifications.Results))
	}

	if !spec.ConfirmExecOnDest {
		return nil
	}

	execEvt, _, err := v3Dst.ConfirmExecOnDest(ctx, spec.Src, messageKey, execTimeout)
	if err != nil {
		return fmt.Errorf("confirm exec on dest: %w", err)
	}
	if spec.ExpectExecFailure {
		if execEvt.State != cciptestinterfaces.ExecutionStateFailure {
			return fmt.Errorf("expected execution failure, got %s", execEvt.State)
		}
	} else if execEvt.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("expected execution success, got %s", execEvt.State)
	}
	return nil
}
