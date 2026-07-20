package chaos

import (
	"context"
	"fmt"
	"testing"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
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
	MsgOpts  cciptestinterfaces.MessageOptions
	SendArgs tcapi.SendArgs

	Outage OutageSpec
	Assert tcapi.AssertMessageOptions
	Run    tcapi.RunConfig

	// AggregatorQualifier selects which committee aggregator to wait on. Empty uses default.
	AggregatorQualifier string

	// ConfirmExecOnDest waits for successful execution on the destination when true.
	ConfirmExecOnDest bool
	ExpectExecFailure bool
}

// RunScenario injects the outage, sends a V3 message, asserts aggregator/indexer state,
// and optionally confirms execution on the destination. The caller must provide lib and
// message fields; this package does not filter chains by family.
func RunScenario(t *testing.T, ctx context.Context, spec ScenarioSpec) error {
	cleanup, err := InjectOutage(ctx, spec.Outage)
	if err != nil {
		return fmt.Errorf("inject outage: %w", err)
	}
	t.Cleanup(cleanup)

	chainMap, err := spec.Lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("chains map: %w", err)
	}
	src, ok := chainMap[spec.Src]
	if !ok {
		return fmt.Errorf("source chain %d not found", spec.Src)
	}
	dst, ok := chainMap[spec.Dst]
	if !ok {
		return fmt.Errorf("dest chain %d not found", spec.Dst)
	}

	sent, err := tcapi.SendV3Message(ctx, src, dst, spec.Dst, spec.Fields, spec.MsgOpts, spec.SendArgs)
	if err != nil {
		return fmt.Errorf("send v3 message: %w", err)
	}
	if sent.MessageID == (protocol.Bytes32{}) {
		return fmt.Errorf("send returned zero message ID")
	}

	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sent.MessageID}
	sentTimeout := spec.Run.SentTimeout(tcapi.DefaultSentTimeout)
	if _, err := src.ConfirmSendOnSource(ctx, spec.Dst, messageKey, sentTimeout); err != nil {
		return fmt.Errorf("confirm send on source: %w", err)
	}

	aggregatorClients, err := spec.Lib.AllAggregators()
	if err != nil {
		return fmt.Errorf("aggregator clients: %w", err)
	}

	var aggregatorClient *ccv.AggregatorClient
	if len(aggregatorClients) > 0 {
		aggregatorClient = aggregatorClients[devenvcommon.DefaultCommitteeVerifierQualifier]

		if spec.AggregatorQualifier != "" && spec.AggregatorQualifier != devenvcommon.DefaultCommitteeVerifierQualifier {
			if client, ok := aggregatorClients[spec.AggregatorQualifier]; ok {
				aggregatorClient = client
			}
		}
	}

	indexers, err := spec.Lib.AllIndexers()
	if err != nil {
		return fmt.Errorf("indexer clients: %w", err)
	}
	var indexerMonitor *ccv.IndexerMonitor
	if len(indexers) > 0 {
		indexerMonitor, err = spec.Lib.IndexerMonitor()
		if err != nil {
			return fmt.Errorf("indexer monitor: %w", err)
		}
	}

	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	result, err := testCtx.AssertMessage(sent.MessageID, spec.Assert)
	if err != nil {
		return fmt.Errorf("assert message: %w", err)
	}
	if aggregatorClient != nil && result.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}
	if indexerMonitor != nil && len(result.IndexedVerifications.Results) != spec.Assert.ExpectedVerifierResults {
		return fmt.Errorf("expected %d indexed verifications, got %d",
			spec.Assert.ExpectedVerifierResults, len(result.IndexedVerifications.Results))
	}

	if !spec.ConfirmExecOnDest {
		return nil
	}

	execTimeout := spec.Run.ExecTimeout(tcapi.DefaultExecTimeout)
	if spec.Assert.Timeout != 0 {
		execTimeout = spec.Run.ExecTimeout(spec.Assert.Timeout)
	}
	execEvt, err := dst.ConfirmExecOnDest(ctx, spec.Src, messageKey, execTimeout)
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
