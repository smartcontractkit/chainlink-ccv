package tcapi

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const (
	defaultExecTimeout = 40 * time.Second
	defaultSentTimeout = 10 * time.Second
)

type tokenTransfer struct {
	tokenAmount  cciptestinterfaces.TokenAmount
	destTokenRef datastore.AddressRef
}

// v3TestCaseBase contains test data that can be specified w/out the environment
// being loaded.
type v3TestCaseBase struct {
	name                     string
	src                      cciptestinterfaces.CCIP17
	dst                      cciptestinterfaces.CCIP17
	msgData                  []byte
	finality                 uint16
	expectFail               bool
	tokenTransfer            *tokenTransfer
	numExpectedReceipts      int
	numExpectedVerifications int
	aggregatorQualifier      string // which aggregator to query (default, secondary, tertiary)
}

// v3TestCase is for tests that use ExtraArgsV3.
type v3TestCase struct {
	v3TestCaseBase

	// These values are "hydrated" from the environment, once we have e.g.
	// the full datastore loaded from the environment.
	receiver protocol.UnknownAddress
	ccvs     []protocol.CCV
	executor protocol.UnknownAddress
	// TODO: is this the best way to do the hydration?
	// pointer means we can do self-reference, but feels weird...
	hydrate func(ctx context.Context, tc *v3TestCase, cfg *ccv.Cfg) bool
}

func (tc *v3TestCase) Name() string {
	return tc.name
}

func (tc *v3TestCase) Run(ctx context.Context, harness TestHarness, cfg *ccv.Cfg) error {
	l := zerolog.Ctx(ctx)
	var (
		receiverStartBalance *big.Int
		destTokenAddress     protocol.UnknownAddress
		tokenAmount          cciptestinterfaces.TokenAmount
	)
	if tc.tokenTransfer != nil {
		tokenAmount = tc.tokenTransfer.tokenAmount
		var err error
		destTokenAddress, err = getContractAddress(cfg, tc.dst.ChainSelector(), tc.tokenTransfer.destTokenRef.Type, tc.tokenTransfer.destTokenRef.Version.String(), tc.tokenTransfer.destTokenRef.Qualifier, "token on destination chain")
		if err != nil {
			return fmt.Errorf("failed to get destination token address: %w", err)
		}
		receiverStartBalance, err = tc.dst.GetTokenBalance(ctx, tc.receiver, destTokenAddress)
		if err != nil {
			return fmt.Errorf("failed to get receiver start balance: %w", err)
		}
		l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("StartBalance", receiverStartBalance.Uint64()).Msg("Receiver start balance")
	}
	seqNo, err := tc.src.GetExpectedNextSequenceNumber(ctx, tc.dst.ChainSelector())
	if err != nil {
		return fmt.Errorf("failed to get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	sendMessageResult, err := tc.src.SendMessage(
		ctx, tc.dst.ChainSelector(), cciptestinterfaces.MessageFields{
			Receiver:    tc.receiver,
			Data:        tc.msgData,
			TokenAmount: tokenAmount,
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
	sentEvent, err := tc.src.WaitOneSentEventBySeqNo(ctx, tc.dst.ChainSelector(), seqNo, defaultSentTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for sent event: %w", err)
	}
	messageID := sentEvent.MessageID

	// Select the appropriate aggregator client based on the test case's aggregatorQualifier
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
	testCtx, cleanupFn := NewTestingContext(ctx, chainMap, aggregatorClient, harness.IndexerMonitor)
	defer cleanupFn()
	result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
		TickInterval:            1 * time.Second,
		ExpectedVerifierResults: tc.numExpectedVerifications,
		Timeout:                 defaultExecTimeout,
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

	e, err := chainMap[tc.dst.ChainSelector()].WaitOneExecEventBySeqNo(ctx, tc.src.ChainSelector(), seqNo, defaultExecTimeout)
	if err != nil {
		return fmt.Errorf("failed to wait for exec event: %w", err)
	}
	if tc.expectFail && e.State != cciptestinterfaces.ExecutionStateFailure {
		return fmt.Errorf("expected execution state failure, got %s", e.State)
	} else if !tc.expectFail && e.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("expected execution state success, got %s", e.State)
	}
	if receiverStartBalance != nil {
		receiverEndBalance, err := tc.dst.GetTokenBalance(ctx, tc.receiver, destTokenAddress)
		if err != nil {
			return fmt.Errorf("failed to get receiver end balance: %w", err)
		}
		if receiverStartBalance.Add(receiverStartBalance, tc.tokenTransfer.tokenAmount.Amount).Cmp(receiverEndBalance) != 0 {
			return fmt.Errorf("expected receiver end balance to be %d, got %d", receiverStartBalance.Add(receiverStartBalance, tc.tokenTransfer.tokenAmount.Amount), receiverEndBalance)
		}
		l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("EndBalance", receiverEndBalance.Uint64()).Msg("t")
	}
	return nil
}

func (tc *v3TestCase) HavePrerequisites(ctx context.Context, cfg *ccv.Cfg) bool {
	// hydrate will hydrate this with needed data and return true if successful, false otherwise.
	return tc.hydrate(ctx, tc, cfg)
}

func getContractAddress(ccvCfg *ccv.Cfg, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) (protocol.UnknownAddress, error) {
	ref, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s: %w",
			contractName, chainSelector, contractType, version, err)
	}
	return protocol.NewUnknownAddressFromHex(ref.Address)
}

func AllBasicExtraArgsV3(src, dest cciptestinterfaces.CCIP17) []TestCase {
	return append(
		append(
			[]TestCase{customExecutorTestCase(src, dest)},
			multiVerifierTestCases(src, dest)...,
		),
		dataSizeTestCases(src, dest)...,
	)
}

func customExecutorTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, dest.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getContractAddress(cfg, src.ChainSelector(), datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{
				{
					CCVAddress: ccv,
					Args:       []byte{},
					ArgsLen:    0,
				},
			}

			executor, err := getContractAddress(cfg, src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.CustomExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor

			return true
		},
	}
}

// multiVerifierTestCases returns test cases for multi-verifier scenarios.
func multiVerifierTestCases(src, dest cciptestinterfaces.CCIP17) []TestCase {
	return []TestCase{
		eoaReceiverDefaultCommitteeVerifierTestCase(src, dest),
		eoaReceiverSecondaryCommitteeVerifierTestCase(src, dest),
		receiverSecondaryVerifierRequiredTestCase(src, dest),
		receiverSecondaryRequiredTertiaryOptionalThreshold1TestCase(src, dest),
		receiverQuaternaryAllThreeVerifiersTestCase(src, dest),
		receiverQuaternaryDefaultAndSecondaryTestCase(src, dest),
		receiverQuaternaryDefaultAndTertiaryTestCase(src, dest),
	}
}

// dataSizeTestCases returns test cases for data size limits (e.g. max data size).
func dataSizeTestCases(src, dest cciptestinterfaces.CCIP17) []TestCase {
	return []TestCase{maxDataSizeTestCase(src, dest)}
}

func maxDataSizeTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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

			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver

			ccv, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}

			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func getCCV(cfg *ccv.Cfg, srcChainSelector uint64, qualifier, contractName string) (protocol.CCV, error) {
	addr, err := getContractAddress(cfg, srcChainSelector, datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), qualifier, contractName)
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

func eoaReceiverDefaultCommitteeVerifierTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			ccv, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func eoaReceiverSecondaryCommitteeVerifierTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			sec, err := getCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			def, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, def}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func receiverSecondaryVerifierRequiredTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			ccv, err := getCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{ccv}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func receiverSecondaryRequiredTertiaryOptionalThreshold1TestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.SecondaryReceiverQualifier, "secondary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			sec, err := getCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{sec, ter}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func receiverQuaternaryAllThreeVerifiersTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec, ter}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func receiverQuaternaryDefaultAndSecondaryTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			sec, err := getCCV(cfg, tc.src.ChainSelector(), common.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, sec}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}

func receiverQuaternaryDefaultAndTertiaryTestCase(src, dest cciptestinterfaces.CCIP17) *v3TestCase {
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
			receiver, err := getContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.QuaternaryReceiverQualifier, "quaternary mock receiver")
			if err != nil {
				return false
			}
			tc.receiver = receiver
			def, err := getCCV(cfg, tc.src.ChainSelector(), common.DefaultCommitteeVerifierQualifier, "default committee verifier proxy")
			if err != nil {
				return false
			}
			ter, err := getCCV(cfg, tc.src.ChainSelector(), common.TertiaryCommitteeVerifierQualifier, "tertiary committee verifier proxy")
			if err != nil {
				return false
			}
			tc.ccvs = []protocol.CCV{def, ter}
			executor, err := getContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			tc.executor = executor
			return true
		},
	}
}
