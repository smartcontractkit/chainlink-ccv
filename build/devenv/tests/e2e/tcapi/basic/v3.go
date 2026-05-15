package basic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// v3TestCaseBase contains test data that can be specified w/out the environment.
type v3TestCaseBase struct {
	name                     string
	src                      cciptestinterfaces.CCIP17
	dst                      cciptestinterfaces.CCIP17
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
	deps     *tcapi.CaseDeps
	receiver protocol.UnknownAddress
	ccvs     []protocol.CCV
	executor protocol.UnknownAddress
	hydrate  func(ctx context.Context, tc *v3TestCase) bool
}

func (tc *v3TestCase) Name() string {
	return tc.name
}

func (tc *v3TestCase) Run(ctx context.Context) error {
	l := zerolog.Ctx(ctx)
	seqNo, err := tc.src.GetExpectedNextSequenceNumber(ctx, tc.dst.ChainSelector())
	if err != nil {
		return fmt.Errorf("failed to get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	sendMessageResult, err := tc.src.SendMessage(
		ctx, tc.dst.ChainSelector(), cciptestinterfaces.MessageFields{
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
	sentEvent, err := tc.src.ConfirmSendOnSource(ctx, tc.dst.ChainSelector(), cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sentEvent.MessageID

	aggregatorClient := tc.deps.AggregatorClients[common.DefaultCommitteeVerifierQualifier]
	if tc.aggregatorQualifier != "" && tc.aggregatorQualifier != common.DefaultCommitteeVerifierQualifier {
		if client, ok := tc.deps.AggregatorClients[tc.aggregatorQualifier]; ok {
			aggregatorClient = client
		}
	}
	chainMap := tc.deps.ChainMap

	offchain := aggregatorClient != nil || tc.deps.IndexerMonitor != nil
	if offchain {
		testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, tc.deps.IndexerMonitor)
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
		if aggregatorClient != nil && result.AggregatedResult == nil {
			return fmt.Errorf("aggregated result is nil")
		}
		if tc.deps.IndexerMonitor != nil && len(result.IndexedVerifications.Results) != tc.numExpectedVerifications {
			return fmt.Errorf("expected %d indexed verifications, got %d", tc.numExpectedVerifications, len(result.IndexedVerifications.Results))
		}
	} else {
		l.Info().Msg("skipping aggregator/indexer assertions (off-chain clients not configured)")
	}

	e, err := chainMap[tc.dst.ChainSelector()].ConfirmExecOnDest(ctx, tc.src.ChainSelector(), cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultExecTimeout)
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

// CustomExecutor returns a test case that uses the custom executor.
func CustomExecutor(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return customExecutor(src, dest, deps)
}

func customExecutor(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "custom executor",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("custom executor test"),
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(dest.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.DefaultReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := tc.deps.CommitteeCCV(src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tc.deps.ResolveAddress(src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.CustomExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverDefaultVerifier returns a test case: EOA receiver and default committee verifier.
func EOAReceiverDefaultVerifier(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return eoaReceiverDefaultVerifier(src, dest, deps)
}

func eoaReceiverDefaultVerifier(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and default committee verifier",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverSecondaryVerifier returns a test case: EOA receiver and secondary committee verifier.
func EOAReceiverSecondaryVerifier(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return eoaReceiverSecondaryVerifier(src, dest, deps)
}

func eoaReceiverSecondaryVerifier(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and secondary committee verifier",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			def, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, def}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryVerifierRequired returns a test case: receiver with secondary verifier required.
func ReceiverSecondaryVerifierRequired(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return receiverSecondaryVerifierRequired(src, dest, deps)
}

func receiverSecondaryVerifierRequired(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ secondary verifier required",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
			aggregatorQualifier:      common.SecondaryCommitteeVerifierQualifier,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.SecondaryReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryRequiredTertiaryOptionalThreshold1 returns a test case: receiver w/ secondary required and tertiary optional threshold=1.
func ReceiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest, deps)
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ secondary required and tertiary optional threshold=1",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
			aggregatorQualifier:      common.SecondaryCommitteeVerifierQualifier,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.SecondaryReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, ter}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutorImpl, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryAllThreeVerifiers returns a test case: receiver w/ default required, secondary and tertiary optional, message specifies all three.
func ReceiverQuaternaryAllThreeVerifiers(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return receiverQuaternaryAllThreeVerifiers(src, dest, deps)
}

func receiverQuaternaryAllThreeVerifiers(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies all three",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      5,
			numExpectedVerifications: 3,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.QuaternaryReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec, ter}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndSecondary returns a test case: receiver w/ default and secondary verifiers.
func ReceiverQuaternaryDefaultAndSecondary(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return receiverQuaternaryDefaultAndSecondary(src, dest, deps)
}

func receiverQuaternaryDefaultAndSecondary(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and secondary",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.QuaternaryReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			sec, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndTertiary returns a test case: receiver w/ default and tertiary verifiers.
func ReceiverQuaternaryDefaultAndTertiary(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return receiverQuaternaryDefaultAndTertiary(src, dest, deps)
}

func receiverQuaternaryDefaultAndTertiary(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and tertiary",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.QuaternaryReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			ter, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, ter}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// MaxDataSize returns a test case that sends the maximum allowed data size.
func MaxDataSize(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return maxDataSize(src, dest, deps)
}

func maxDataSize(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "max data size",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			maxDataBytes, err := tc.dst.GetMaxDataBytes(ctx, tc.dst.ChainSelector())
			if err != nil {
				return false
			}
			tc.msgData = bytes.Repeat([]byte("a"), int(maxDataBytes))
			receiver, err := tc.deps.ResolveAddress(tc.dst.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleMockReceiver, Qualifier: common.DefaultReceiverQualifier})
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
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
func EOAReceiverDefaultVerifier_SafeTag(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) tcapi.TestCase {
	return eoaReceiverDefaultVerifierSafeTag(src, dest, deps)
}

func eoaReceiverDefaultVerifierSafeTag(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps) *v3TestCase {
	return &v3TestCase{
		deps: deps,
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver, default committee verifier, safe-tag finality",
			src:                      src,
			dst:                      dest,
			finality:                 protocol.FinalityWaitForSafe,
			msgData:                  []byte("safe-tag finality test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			receiver, err := tc.dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := tc.deps.CommitteeCCV(tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier)
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tc.deps.ResolveAddress(tc.src.ChainSelector(), tcapi.ContractRef{Role: tcapi.RoleExecutor, Qualifier: common.DefaultExecutorQualifier})
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// All returns all basic v3 messaging test cases (custom executor, multi-verifier, max data size).
func All(ctx context.Context, env *deployment.Environment, addressResolvers tcapi.AddressResolvers, opts ...tcapi.CaseOption) ([]tcapi.TestCase, error) {
	deps, err := tcapi.BuildCaseDeps(ctx, env, addressResolvers, opts...)
	if err != nil {
		return nil, err
	}
	src := deps.ChainMap[deps.SrcSelector]
	dst := deps.ChainMap[deps.DstSelector]
	return []tcapi.TestCase{
		customExecutor(src, dst, deps),
		eoaReceiverDefaultVerifier(src, dst, deps),
		eoaReceiverDefaultVerifierSafeTag(src, dst, deps),
		eoaReceiverSecondaryVerifier(src, dst, deps),
		receiverSecondaryVerifierRequired(src, dst, deps),
		receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dst, deps),
		receiverQuaternaryAllThreeVerifiers(src, dst, deps),
		receiverQuaternaryDefaultAndSecondary(src, dst, deps),
		receiverQuaternaryDefaultAndTertiary(src, dst, deps),
		maxDataSize(src, dst, deps),
	}, nil
}
