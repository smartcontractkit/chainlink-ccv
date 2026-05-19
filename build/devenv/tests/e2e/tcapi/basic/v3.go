package basic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
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
}

// v3TestCase is for tests that use ExtraArgsV3.
type v3TestCase struct {
	v3TestCaseBase
	receiver protocol.UnknownAddress
	ccvs     []protocol.CCV
	executor protocol.UnknownAddress
	hydrate  func(ctx context.Context, tc *v3TestCase) bool
}

func (tc *v3TestCase) Name() string {
	return tc.name
}

func (tc *v3TestCase) Run(ctx context.Context) error {
	chainMap, err := tc.lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chains map: %w", err)
	}
	src, ok := chainMap[tc.src]
	if !ok {
		return fmt.Errorf("source chain not found: %d", tc.src)
	}
	dst, ok := chainMap[tc.dst]
	if !ok {
		return fmt.Errorf("destination chain not found: %d", tc.dst)
	}
	l := zerolog.Ctx(ctx)
	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, tc.dst)
	if err != nil {
		return fmt.Errorf("failed to get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	sendMessageResult, err := src.SendMessage(
		ctx, tc.dst, cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			Data:     tc.msgData,
		}, cciptestinterfaces.MessageOptions{
			ExecutionGasLimit: 200_000,
			FinalityConfig:    tc.finality,
			Executor:          tc.executor,
			CCVs:              tc.ccvs,
		}, 3)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	if len(sendMessageResult.ReceiptIssuers) != tc.numExpectedReceipts {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedReceipts, len(sendMessageResult.ReceiptIssuers))
	}
	sentEvent, err := src.ConfirmSendOnSource(ctx, tc.dst, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sentEvent.MessageID

	aggregatorClients, err := tc.lib.AllAggregators()
	if err != nil {
		return fmt.Errorf("failed to get aggregator clients: %w", err)
	}
	aggregatorClient := aggregatorClients[common.DefaultCommitteeVerifierQualifier]
	if tc.aggregatorQualifier != "" && tc.aggregatorQualifier != common.DefaultCommitteeVerifierQualifier {
		if client, ok := aggregatorClients[tc.aggregatorQualifier]; ok {
			aggregatorClient = client
		}
	}
	indexerMonitor, err := tc.lib.IndexerMonitor()
	if err != nil {
		return fmt.Errorf("failed to get indexer monitor: %w", err)
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	result, err := testCtx.AssertMessage(messageID, tcapi.AssertMessageOptions{
		TickInterval:            1 * time.Second,
		ExpectedVerifierResults: tc.numExpectedVerifications,
		Timeout:                 tcapi.DefaultExecTimeout,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	if err != nil {
		return fmt.Errorf("failed to assert message: %w", err)
	}
	if result.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}
	if len(result.IndexedVerifications.Results) != tc.numExpectedVerifications {
		return fmt.Errorf("expected %d indexed verifications, got %d", tc.numExpectedVerifications, len(result.IndexedVerifications.Results))
	}

	e, err := dst.ConfirmExecOnDest(ctx, tc.src, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultExecTimeout)
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
	return tc.hydrate(ctx, tc)
}

func getCommitteeCCV(resolver chainreg.AddressResolver, ds datastore.DataStore, srcChainSelector uint64, qualifier string) (protocol.CCV, error) {
	addr, err := resolver.GetCommitteeCCV(ds, srcChainSelector, qualifier)
	if err != nil {
		return protocol.CCV{}, err
	}

	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

// v3Env holds devenv handles loaded for v3 test case hydration.
type v3Env struct {
	DS          datastore.DataStore
	Dst         cciptestinterfaces.CCIP17
	SrcResolver chainreg.AddressResolver
	DstResolver chainreg.AddressResolver
}

func loadV3Env(ctx context.Context, lib ccv.Lib, src, dst uint64) (v3Env, bool) {
	var env v3Env

	ds, err := lib.DataStore()
	if err != nil {
		return env, false
	}
	env.DS = ds

	chainMap, err := lib.ChainsMap(ctx)
	if err != nil {
		return env, false
	}

	dstChain, ok := chainMap[dst]
	if !ok {
		return env, false
	}
	env.Dst = dstChain

	srcFamily, err := chain_selectors.GetSelectorFamily(src)
	if err != nil {
		return env, false
	}
	dstFamily, err := chain_selectors.GetSelectorFamily(dst)
	if err != nil {
		return env, false
	}

	srcReg, err := chainreg.GetRegistry().Get(srcFamily)
	if err != nil {
		return env, false
	}
	dstReg, err := chainreg.GetRegistry().Get(dstFamily)
	if err != nil {
		return env, false
	}
	if srcReg.AddressResolver == nil || dstReg.AddressResolver == nil {
		return env, false
	}
	env.SrcResolver = srcReg.AddressResolver
	env.DstResolver = dstReg.AddressResolver

	return env, true
}

// CustomExecutor returns a test case that uses the custom executor.
func CustomExecutor(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return customExecutor(lib, src, dest)
}

func customExecutor(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.DefaultReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
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
func EOAReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return eoaReceiverDefaultVerifier(lib, src, dest)
}

func eoaReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.Dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
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

// EOAReceiverSecondaryVerifier returns a test case: EOA receiver and secondary committee verifier.
func EOAReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return eoaReceiverSecondaryVerifier(lib, src, dest)
}

func eoaReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.Dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver

			sec, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			def, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
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
func ReceiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return receiverSecondaryVerifierRequired(lib, src, dest)
}

func receiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.SecondaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
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
func ReceiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest)
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.SecondaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			sec, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
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
func ReceiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return receiverQuaternaryAllThreeVerifiers(lib, src, dest)
}

func receiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
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
func ReceiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return receiverQuaternaryDefaultAndSecondary(lib, src, dest)
}

func receiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			def, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.SecondaryCommitteeVerifierQualifier)
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
func ReceiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return receiverQuaternaryDefaultAndTertiary(lib, src, dest)
}

func receiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.QuaternaryReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.TertiaryCommitteeVerifierQualifier)
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
func MaxDataSize(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return maxDataSize(lib, src, dest)
}

func maxDataSize(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			maxDataBytes, err := env.Dst.GetMaxDataBytes(ctx, tc.dst)
			if err != nil {
				return false
			}
			tc.msgData = bytes.Repeat([]byte("a"), int(maxDataBytes))

			receiver, err := env.DstResolver.GetContractReceiver(env.DS, tc.dst, common.DefaultReceiverQualifier)
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
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
func EOAReceiverDefaultVerifier_SafeTag(lib ccv.Lib, src, dest uint64) tcapi.TestCase {
	return eoaReceiverDefaultVerifierSafeTag(lib, src, dest)
}

func eoaReceiverDefaultVerifierSafeTag(lib ccv.Lib, src, dest uint64) *v3TestCase {
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
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			env, ok := loadV3Env(ctx, tc.lib, tc.src, tc.dst)
			if !ok {
				return false
			}
			receiver, err := env.Dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getCommitteeCCV(env.SrcResolver, env.DS, tc.src, common.DefaultCommitteeVerifierQualifier)
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

// All returns all basic v3 messaging test cases (custom executor, multi-verifier, max data size).
func All(lib ccv.Lib, src, dest uint64) []tcapi.TestCase {
	return []tcapi.TestCase{
		customExecutor(lib, src, dest),
		eoaReceiverDefaultVerifier(lib, src, dest),
		eoaReceiverDefaultVerifierSafeTag(lib, src, dest),
		eoaReceiverSecondaryVerifier(lib, src, dest),
		receiverSecondaryVerifierRequired(lib, src, dest),
		receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest),
		receiverQuaternaryAllThreeVerifiers(lib, src, dest),
		receiverQuaternaryDefaultAndSecondary(lib, src, dest),
		receiverQuaternaryDefaultAndTertiary(lib, src, dest),
		maxDataSize(lib, src, dest),
	}
}
