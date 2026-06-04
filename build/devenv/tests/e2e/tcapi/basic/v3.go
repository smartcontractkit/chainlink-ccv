package basic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
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
	sendConfig               tcapi.SendArgs
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
	sendMessageResult, err := tcapi.SendV3Message(ctx, src, dst, tc.dst,
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			Data:     tc.msgData,
		},
		cciptestinterfaces.MessageOptions{
			FinalityConfig: tc.finality,
			Executor:       tc.executor,
			CCVs:           tc.ccvs,
		},
		tc.sendConfig,
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
	_, err = src.ConfirmSendOnSource(ctx, tc.dst, messageKey, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sendMessageResult.MessageID

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

	e, err := dst.ConfirmExecOnDest(ctx, tc.src, messageKey, tcapi.DefaultExecTimeout)
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

func getCommitteeCCV(ds datastore.DataStore, srcChainSelector uint64, qualifier, contractName string) (protocol.CCV, error) {
	addr, err := tcapi.GetContractAddress(ds, srcChainSelector, datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType), versioned_verifier_resolver.Version.String(), qualifier, contractName)
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

// CustomExecutor returns a test case that uses the custom executor.
func CustomExecutor(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return customExecutor(lib, src, dest, cfg)
}

func customExecutor(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, dest, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccvAddr, err := tcapi.GetContractAddress(ds, src, datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType), versioned_verifier_resolver.Version.String(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}}
			executorAddr, err := tcapi.GetContractAddress(ds, src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.CustomExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverDefaultVerifier returns a test case: EOA receiver and default committee verifier.
func EOAReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return eoaReceiverDefaultVerifier(lib, src, dest, cfg)
}

func eoaReceiverDefaultVerifier(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return false
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return false
			}
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// EOAReceiverSecondaryVerifier returns a test case: EOA receiver and secondary committee verifier.
func EOAReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return eoaReceiverSecondaryVerifier(lib, src, dest, cfg)
}

func eoaReceiverSecondaryVerifier(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return false
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return false
			}
			receiver, err := dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := getCommitteeCCV(ds, tc.src, common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			def, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, def}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryVerifierRequired returns a test case: receiver with secondary verifier required.
func ReceiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return receiverSecondaryVerifierRequired(lib, src, dest, cfg)
}

func receiverSecondaryVerifierRequired(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(ds, tc.src, common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverSecondaryRequiredTertiaryOptionalThreshold1 returns a test case: receiver w/ secondary required and tertiary optional threshold=1.
func ReceiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest, cfg)
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := getCommitteeCCV(ds, tc.src, common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(ds, tc.src, common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, ter}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), executor.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryAllThreeVerifiers returns a test case: receiver w/ default required, secondary and tertiary optional, message specifies all three.
func ReceiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return receiverQuaternaryAllThreeVerifiers(lib, src, dest, cfg)
}

func receiverQuaternaryAllThreeVerifiers(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(ds, tc.src, common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(ds, tc.src, common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec, ter}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndSecondary returns a test case: receiver w/ default and secondary verifiers.
func ReceiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return receiverQuaternaryDefaultAndSecondary(lib, src, dest, cfg)
}

func receiverQuaternaryDefaultAndSecondary(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCommitteeCCV(ds, tc.src, common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// ReceiverQuaternaryDefaultAndTertiary returns a test case: receiver w/ default and tertiary verifiers.
func ReceiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return receiverQuaternaryDefaultAndTertiary(lib, src, dest, cfg)
}

func receiverQuaternaryDefaultAndTertiary(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCommitteeCCV(ds, tc.src, common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, ter}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// MaxDataSize returns a test case that sends the maximum allowed data size.
func MaxDataSize(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return maxDataSize(lib, src, dest, cfg)
}

func maxDataSize(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return false
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return false
			}
			maxDataBytes, err := dst.GetMaxDataBytes(ctx, tc.dst)
			if err != nil {
				return false
			}
			tc.msgData = bytes.Repeat([]byte("a"), int(maxDataBytes))
			receiver, err := tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
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
func EOAReceiverDefaultVerifier_SafeTag(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) tcapi.TestCase {
	return eoaReceiverDefaultVerifierSafeTag(lib, src, dest, cfg)
}

func eoaReceiverDefaultVerifierSafeTag(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) *v3TestCase {
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
			sendConfig:               cfg,
		},
		hydrate: func(ctx context.Context, tc *v3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return false
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return false
			}
			receiver, err := dst.GetEOAReceiverAddress()
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCommitteeCCV(ds, tc.src, common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executorAddr, err := tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executorAddr
			return true
		},
	}
}

// All returns all basic v3 messaging test cases (custom executor, multi-verifier, max data size).
func All(lib ccv.Lib, src, dest uint64, cfg tcapi.SendArgs) []tcapi.TestCase {
	return []tcapi.TestCase{
		customExecutor(lib, src, dest, cfg),
		eoaReceiverDefaultVerifier(lib, src, dest, cfg),
		eoaReceiverDefaultVerifierSafeTag(lib, src, dest, cfg),
		eoaReceiverSecondaryVerifier(lib, src, dest, cfg),
		receiverSecondaryVerifierRequired(lib, src, dest, cfg),
		receiverSecondaryRequiredTertiaryOptionalThreshold1(lib, src, dest, cfg),
		receiverQuaternaryAllThreeVerifiers(lib, src, dest, cfg),
		receiverQuaternaryDefaultAndSecondary(lib, src, dest, cfg),
		receiverQuaternaryDefaultAndTertiary(lib, src, dest, cfg),
		maxDataSize(lib, src, dest, cfg),
	}
}
