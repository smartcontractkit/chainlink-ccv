package basic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// v3TestCaseBase contains test data that can be specified w/out the environment.
type v3TestCaseBase struct {
	name                     string
	src                      cciptestinterfaces.CCIP17
	dst                      cciptestinterfaces.CCIP17
	msgData                  []byte
	finality                 uint16
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
	hydrate  func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool
}

func (tc *v3TestCase) Name() string {
	return tc.name
}

func (tc *v3TestCase) Run(ctx context.Context, harness tcapi.TestHarness, cfg *ccv.Cfg) error {
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
			Version:           3,
			ExecutionGasLimit: 200_000,
			FinalityConfig:    tc.finality,
			Executor:          tc.executor,
			CCVs:              tc.ccvs,
		})
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	if len(sendMessageResult.ReceiptIssuers) != tc.numExpectedReceipts {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedReceipts, len(sendMessageResult.ReceiptIssuers))
	}
	sentEvent, err := tc.src.WaitOneSentEventBySeqNo(ctx, tc.dst.ChainSelector(), seqNo, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sentEvent.MessageID

	aggregatorClient := harness.AggregatorClients[common.DefaultCommitteeVerifierQualifier]
	if tc.aggregatorQualifier != "" && tc.aggregatorQualifier != common.DefaultCommitteeVerifierQualifier {
		if client, ok := harness.AggregatorClients[tc.aggregatorQualifier]; ok {
			aggregatorClient = client
		}
	}
	chainMap, err := harness.Lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chains map: %w", err)
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, harness.IndexerMonitor)
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

	e, err := chainMap[tc.dst.ChainSelector()].WaitOneExecEventBySeqNo(ctx, tc.src.ChainSelector(), seqNo, tcapi.DefaultExecTimeout)
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

func (tc *v3TestCase) HavePrerequisites(ctx context.Context, cfg *ccv.Cfg) bool {
	return tc.hydrate(ctx, tc, cfg)
}

func getCommitteeCCV(cfg *ccv.Cfg, srcChainSelector uint64, qualifier, contractName string) (protocol.CCV, error) {
	addr, err := tcapi.GetContractAddress(cfg, srcChainSelector, datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), qualifier, contractName)
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

// CustomExecutor returns a test case that uses the custom executor.
func CustomExecutor(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return customExecutor(src, dest)
}

func customExecutor(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
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
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, dest.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccvAddr, err := tcapi.GetContractAddress(cfg, src.ChainSelector(), datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}}
			executorAddr, err := tcapi.GetContractAddress(cfg, src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.CustomExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverDefaultVerifier returns a test case: EOA receiver and default committee verifier.
func EOAReceiverDefaultVerifier(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return eoaReceiverDefaultVerifier(src, dest)
}

func eoaReceiverDefaultVerifier(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and default committee verifier",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      3,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tc.dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverSecondaryVerifier returns a test case: EOA receiver and secondary committee verifier.
func EOAReceiverSecondaryVerifier(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return eoaReceiverSecondaryVerifier(src, dest)
}

func eoaReceiverSecondaryVerifier(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "EOA receiver and secondary committee verifier",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tc.dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			def, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, def}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryVerifierRequired returns a test case: receiver with secondary verifier required.
func ReceiverSecondaryVerifierRequired(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return receiverSecondaryVerifierRequired(src, dest)
}

func receiverSecondaryVerifierRequired(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
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
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryRequiredTertiaryOptionalThreshold1 returns a test case: receiver w/ secondary required and tertiary optional threshold=1.
func ReceiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest)
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
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
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, ter}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryAllThreeVerifiers returns a test case: receiver w/ default required, secondary and tertiary optional, message specifies all three.
func ReceiverQuaternaryAllThreeVerifiers(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return receiverQuaternaryAllThreeVerifiers(src, dest)
}

func receiverQuaternaryAllThreeVerifiers(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies all three",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      5,
			numExpectedVerifications: 3,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec, ter}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndSecondary returns a test case: receiver w/ default and secondary verifiers.
func ReceiverQuaternaryDefaultAndSecondary(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return receiverQuaternaryDefaultAndSecondary(src, dest)
}

func receiverQuaternaryDefaultAndSecondary(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and secondary",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndTertiary returns a test case: receiver w/ default and tertiary verifiers.
func ReceiverQuaternaryDefaultAndTertiary(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return receiverQuaternaryDefaultAndTertiary(src, dest)
}

func receiverQuaternaryDefaultAndTertiary(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and tertiary",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			msgData:                  []byte("multi-verifier test"),
			numExpectedReceipts:      4,
			numExpectedVerifications: 2,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, ter}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// MaxDataSize returns a test case that sends the maximum allowed data size.
func MaxDataSize(src, dest cciptestinterfaces.CCIP17) tcapi.TestCase {
	return maxDataSize(src, dest)
}

func maxDataSize(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
	return &v3TestCase{
		v3TestCaseBase: v3TestCaseBase{
			name:                     "max data size",
			src:                      src,
			dst:                      dest,
			finality:                 1,
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool {
			maxDataBytes, err := tc.dst.GetMaxDataBytes(ctx, tc.dst.ChainSelector())
			if err != nil {
				return false
			}
			tc.msgData = bytes.Repeat([]byte("a"), int(maxDataBytes))
			receiver, err := tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// All returns all basic v3 messaging test cases (custom executor, multi-verifier, max data size).
func All(src, dest cciptestinterfaces.CCIP17) []tcapi.TestCase {
	return []tcapi.TestCase{
		customExecutor(src, dest),
		eoaReceiverDefaultVerifier(src, dest),
		eoaReceiverSecondaryVerifier(src, dest),
		receiverSecondaryVerifierRequired(src, dest),
		receiverSecondaryRequiredTertiaryOptionalThreshold1(src, dest),
		receiverQuaternaryAllThreeVerifiers(src, dest),
		receiverQuaternaryDefaultAndSecondary(src, dest),
		receiverQuaternaryDefaultAndTertiary(src, dest),
		maxDataSize(src, dest),
	}
}
