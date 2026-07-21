package tcapi

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// V3MsgConifg configures RunV3MessageLifecycle, the standard V3 send -> confirm-send-on-source
// -> offchain assert -> (optional) confirm-exec-on-destination pipeline shared by basic
// messaging tests, chaos scenarios, and token transfer tests.
type V3MsgConifg struct {
	Src, Dst uint64
	Fields   cciptestinterfaces.MessageFields
	Opts     cciptestinterfaces.MessageOptions
	SendArgs SendArgs
	Run      RunConfig

	// Assert configures the offchain AssertMessage call. When Assert.Timeout is zero it
	// falls back to the computed exec timeout.
	Assert AssertMessageOptions

	// ExecTimeout is the fallback used for ConfirmExecOnDest and (when Assert.Timeout is
	// zero) for AssertMessage. A non-zero Run.ConfirmExecTimeout overrides it.
	ExecTimeout time.Duration

	// ExpectedReceiptIssuers, when non-zero, is checked against the sent message's
	// ReceiptIssuers immediately after send (before waiting for on-source confirmation).
	// Zero skips the check.
	ExpectedReceiptIssuers int

	AggregatorQualifier string
	ConfirmExec         bool
	ExpectExecFail      bool
}

// RunV3MessageLifecycle runs the standard V3 message lifecycle: resolves chains from lib
// (or uses pre-resolved SrcV3/DstV3), builds and sends a V3 message, confirms the send on
// source, sets up offchain clients, asserts offchain state, and optionally confirms
// execution on the destination. It is the single entry point shared by basic messaging
// tests, chaos scenarios, and token transfer tests.
func RunV3MessageLifecycle(ctx context.Context, lib ccv.Lib, cfg V3MsgConifg) error {
	src, err := lib.V3Source(ctx, cfg.Src)
	if err != nil {
		return fmt.Errorf("source chain %d does not support V3 message: %w", cfg.Src, err)
	}
	dst, err := lib.V3Destination(ctx, cfg.Dst)
	if err != nil {
		return fmt.Errorf("destination chain %d does not support V3 message: %w", cfg.Dst, err)
	}

	sent, err := SendV3Message(ctx, src, dst, cfg.Fields, cfg.Opts, cfg.SendArgs)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	if cfg.ExpectedReceiptIssuers != 0 && len(sent.ReceiptIssuers) != cfg.ExpectedReceiptIssuers {
		return fmt.Errorf("expected %d receipt issuers, got %d", cfg.ExpectedReceiptIssuers, len(sent.ReceiptIssuers))
	}
	if sent.MessageID == (protocol.Bytes32{}) {
		return fmt.Errorf("send returned zero message ID")
	}
	if sent.Message != nil {
		zerolog.Ctx(ctx).Info().Uint64("SeqNo", uint64(sent.Message.SequenceNumber)).Msg("Sent message")
	}

	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sent.MessageID}
	sentTimeout := cfg.Run.SentTimeout(DefaultSentTimeout)
	if _, err := src.ConfirmSendOnSource(ctx, cfg.Dst, messageKey, sentTimeout); err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}

	aggregatorClient, indexerMonitor, err := SetupOffchainClients(lib, cfg.AggregatorQualifier)
	if err != nil {
		return err
	}
	testCtx, cleanupFn := NewTestingContext(ctx, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	execTimeout := cfg.Run.ExecTimeout(cfg.ExecTimeout)
	if execTimeout == 0 {
		execTimeout = DefaultExecTimeout
	}

	assertOpts := cfg.Assert
	if assertOpts.Timeout == 0 {
		assertOpts.Timeout = execTimeout
	}

	result, err := testCtx.AssertMessage(sent.MessageID, assertOpts)
	if err != nil {
		return fmt.Errorf("failed to assert message: %w", err)
	}
	if aggregatorClient != nil && result.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}
	if indexerMonitor != nil && len(result.IndexedVerifications.Results) != assertOpts.ExpectedVerifierResults {
		return fmt.Errorf("expected %d indexed verifications, got %d",
			assertOpts.ExpectedVerifierResults, len(result.IndexedVerifications.Results))
	}

	if !cfg.ConfirmExec {
		return nil
	}

	execEvt, err := dst.ConfirmExecOnDest(ctx, cfg.Src, messageKey, execTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for exec event: %w", err)
	}
	if cfg.ExpectExecFail {
		if execEvt.State != cciptestinterfaces.ExecutionStateFailure {
			return fmt.Errorf("expected execution state failure, got %s", execEvt.State)
		}
	} else if execEvt.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("expected execution state success, got %s", execEvt.State)
	}
	return nil
}
