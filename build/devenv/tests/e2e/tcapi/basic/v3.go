package basic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// v3TestCaseBase contains test data that can be specified w/out the environment.
type v3TestCaseBase struct {
	lib                      ccv.Lib
	name                     string
	src                      uint64
	dst                      uint64
	msgData                  []byte
	finality                 protocol.Finality
	expectFail               bool
	numExpectedReceipts      int
	numExpectedVerifications int
	aggregatorQualifier      string
	args                     Args
}

// v3TestCase is for tests that use ExtraArgsV3.
type v3TestCase struct {
	v3TestCaseBase
	receiver protocol.UnknownAddress
	ccvs     []protocol.CCV
	executor protocol.UnknownAddress
	hydrate  func(ctx context.Context, tc *v3TestCase) bool
	hydrated bool
}

func (tc *v3TestCase) Name() string {
	return tc.name
}

func (tc *v3TestCase) ensureHydrated(ctx context.Context) error {
	if tc.hydrated {
		return nil
	}
	if tc.hydrate == nil {
		return fmt.Errorf("%s: missing hydrate func", tc.name)
	}
	if !tc.hydrate(ctx, tc) {
		return fmt.Errorf("%s: prerequisites not met", tc.name)
	}
	tc.hydrated = true
	return nil
}

func (tc *v3TestCase) Run(ctx context.Context) error {
	if err := tc.ensureHydrated(ctx); err != nil {
		return err
	}
	v3Src, err := tc.lib.V3Source(ctx, tc.src)
	if err != nil {
		return fmt.Errorf("source chain %d does not support V3 message: %w", tc.src, err)
	}
	v3Dst, err := tc.lib.V3Destination(ctx, tc.dst)
	if err != nil {
		return fmt.Errorf("destination chain %d does not support V3 message: %w", tc.dst, err)
	}
	l := zerolog.Ctx(ctx)
	sendMessageResult, err := tcapi.SendV3Message(ctx, v3Src, v3Dst,
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			Data:     tc.msgData,
		},
		cciptestinterfaces.MessageOptions{
			FinalityConfig: tc.finality,
			Executor:       tc.executor,
			CCVs:           tc.ccvs,
		},
		tc.args.Send,
	)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	if len(sendMessageResult.ReceiptIssuers) != tc.numExpectedReceipts {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedReceipts, len(sendMessageResult.ReceiptIssuers))
	}
	if sendMessageResult.MessageID == (protocol.Bytes32{}) {
		return fmt.Errorf("send returned zero message ID")
	}
	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sendMessageResult.MessageID}
	if sendMessageResult.Message != nil {
		l.Info().Uint64("SeqNo", uint64(sendMessageResult.Message.SequenceNumber)).Msg("Sent message")
	}
	sentTimeout := tc.args.Run.SentTimeout(tcapi.DefaultSentTimeout)
	execTimeout := tc.args.Run.ExecTimeout(tcapi.DefaultExecTimeout)
	_, err = v3Src.ConfirmSendOnSource(ctx, tc.dst, messageKey, sentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sendMessageResult.MessageID

	aggregatorClient, indexerMonitor, err := tcapi.SetupOffchainClients(tc.lib, tc.aggregatorQualifier)
	if err != nil {
		return err
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	result, err := testCtx.AssertMessage(messageID, tcapi.AssertMessageOptions{
		TickInterval:            1 * time.Second,
		ExpectedVerifierResults: tc.numExpectedVerifications,
		Timeout:                 execTimeout,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	if err != nil {
		return fmt.Errorf("failed to assert message: %w", err)
	}
	if aggregatorClient != nil && result.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}
	if indexerMonitor != nil && len(result.IndexedVerifications.Results) != tc.numExpectedVerifications {
		return fmt.Errorf("expected %d indexed verifications, got %d", tc.numExpectedVerifications, len(result.IndexedVerifications.Results))
	}

	e, err := v3Dst.ConfirmExecOnDest(ctx, tc.src, messageKey, execTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for exec event: %w", err)
	}
	if tc.expectFail && e.State != cciptestinterfaces.ExecutionStateFailure {
		return fmt.Errorf("expected execution state failure, got %s", e.State)
	} else if !tc.expectFail && e.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("expected execution state success, got %s", e.State)
	}
	return nil
}

func (tc *v3TestCase) HavePrerequisites(ctx context.Context) bool {
	return tc.ensureHydrated(ctx) == nil
}

// CustomExecutor returns a test case that uses the custom executor.
func CustomExecutor(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return customExecutor(lib, src, dest, args)
}

func customExecutor(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "custom executor",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("custom executor test"),
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.DefaultReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.CustomExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverDefaultVerifier returns a test case: EOA receiver and default committee verifier.
func EOAReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return eoaReceiverDefaultVerifier(lib, src, dest, args)
}

func eoaReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and default committee verifier",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, ccvs, executor, err := tcapi.ResolveV3SendAddresses(ctx, tc.lib, tc.src, tc.dst)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			tc.ccvs = ccvs
			tc.executor = executor
			return true
		},
	}
}

// EOAReceiverSecondaryVerifier returns a test case: EOA receiver and secondary committee verifier.
func EOAReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return eoaReceiverSecondaryVerifier(lib, src, dest, args)
}

func eoaReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and secondary committee verifier",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.Dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver

			sec, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			def, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, def}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryVerifierRequired returns a test case: receiver with secondary verifier required.
func ReceiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return receiverSecondaryVerifierRequired(lib, src, dest, args)
}

func receiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ secondary verifier required",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
			aggregatorQualifier:      common.SecondaryCommitteeVerifierQualifier,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.SecondaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryRequiredTertiaryOptionalThreshold1 returns a test case: receiver w/ secondary required and tertiary optional threshold=1.
func ReceiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest, args)
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ secondary required and tertiary optional threshold=1",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
			aggregatorQualifier:      common.SecondaryCommitteeVerifierQualifier,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.SecondaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			sec, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, ter}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr

			return true
		},
	}
}

// ReceiverQuaternaryAllThreeVerifiers returns a test case: receiver w/ default required, secondary and tertiary optional, message specifies all three.
func ReceiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return receiverQuaternaryAllThreeVerifiers(lib, src, dest, args)
}

func receiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies all three",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      5,
			numExpectedVerifications: 3,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec, ter}
			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndSecondary returns a test case: receiver w/ default and secondary verifiers.
func ReceiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return receiverQuaternaryDefaultAndSecondary(lib, src, dest, args)
}

func receiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and secondary",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			def, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr

			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndTertiary returns a test case: receiver w/ default and tertiary verifiers.
func ReceiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return receiverQuaternaryDefaultAndTertiary(lib, src, dest, args)
}

func receiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and tertiary",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, ter}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// MaxDataSize returns a test case that sends the maximum allowed data size.
func MaxDataSize(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return maxDataSize(lib, src, dest, args)
}

func maxDataSize(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "max data size",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 1,
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := tcapi.LoadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			maxDataSizeProvider, ok := env.Dst.(cciptestinterfaces.MaxDataSizeProvider)
			if !ok {
				return false
			}
			maxDataBytes, err := maxDataSizeProvider.GetMaxDataBytes(ctx, tc.dst)
			if err != nil {
				return false
			}
			tc.msgData = bytes.Repeat([]byte("a"), int(maxDataBytes))

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.DefaultReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := tcapi.GetCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}

			executorAddr, err := env.SrcResolver.GetExecutor(env.DS, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverDefaultVerifier_SafeTag returns a test case identical to EOAReceiverDefaultVerifier
// but with the finality field set to FinalityWaitForSafe (0x00010000), exercising the Ethereum
// `safe` head fast-confirmation path end-to-end.
func EOAReceiverDefaultVerifier_SafeTag(lib ccv.Lib, src, dest uint64, args Args) tcapi.TestCase {
	return eoaReceiverDefaultVerifierSafeTag(lib, src, dest, args)
}

func eoaReceiverDefaultVerifierSafeTag(lib ccv.Lib, src, dest uint64, args Args) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver, default committee verifier, safe-tag finality",
			lib:                      lib,
			src:                      src,
			dst:                      dest,
			finality:                 protocol.FinalityWaitForSafe,
			msgData:                  []byte("safe-tag finality test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
			args:                     args,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, ccvs, executor, err := tcapi.ResolveV3SendAddresses(ctx, tc.lib, tc.src, tc.dst)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			tc.ccvs = ccvs
			tc.executor = executor
			return true
		},
	}
}

// All returns all basic v3 messaging test cases (custom executor, multi-verifier, max data size).
func All(lib ccv.Lib, src, dest uint64, args Args) []tcapi.TestCase {
	return []tcapi.TestCase{
		customExecutor(lib, src, dest, args),
		eoaReceiverDefaultVerifier(lib, src, dest, args),
		eoaReceiverDefaultVerifierSafeTag(lib, src, dest, args),
		eoaReceiverSecondaryVerifier(lib, src, dest, args),
		receiverSecondaryVerifierRequired(lib, src, dest, args),
		receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest, args),
		receiverQuaternaryAllThreeVerifiers(lib, src, dest, args),
		receiverQuaternaryDefaultAndSecondary(lib, src, dest, args),
		receiverQuaternaryDefaultAndTertiary(lib, src, dest, args),
		maxDataSize(lib, src, dest, args),
	}
}
