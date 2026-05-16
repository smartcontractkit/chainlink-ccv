package token_transfer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

const (
	tokenTransferAmount      = 1000
	tokenTransferExecTimeout = 45 * time.Second
)

type tokenTransferV3TestCaseBase struct {
	name            string
	src             cciptestinterfaces.CCIP17
	dst             cciptestinterfaces.CCIP17
	combo           common.TokenCombination
	finalityConfig  protocol.Finality
	useEOAReceiver  bool
	numExpectedRecv int
	numExpectedVer  int
}

type tokenTransferV3TestCase struct {
	tokenTransferV3TestCaseBase
	deps      *tcapi.CaseDeps
	sender    protocol.UnknownAddress
	receiver  protocol.UnknownAddress
	srcToken  protocol.UnknownAddress
	destToken protocol.UnknownAddress
	executor  protocol.UnknownAddress
	hydrate   func(ctx context.Context, tc *tokenTransferV3TestCase) bool
}

func (tc *tokenTransferV3TestCase) Name() string {
	return tc.name
}

func (tc *tokenTransferV3TestCase) Run(ctx context.Context) error {
	l := zerolog.Ctx(ctx)
	startBal, err := tc.dst.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver start balance: %w", err)
	}
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver start balance")

	srcStartBal, err := tc.src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender start balance: %w", err)
	}
	l.Info().Str("Sender", tc.sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sender start balance")

	seqNo, err := tc.src.GetExpectedNextSequenceNumber(ctx, tc.dst.ChainSelector())
	if err != nil {
		return fmt.Errorf("get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("expecting sequence number")

	sendRes, err := tc.src.SendMessage(
		ctx, tc.dst.ChainSelector(),
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       big.NewInt(tokenTransferAmount),
				TokenAddress: tc.srcToken,
			},
		},
		cciptestinterfaces.MessageOptions{
			ExecutionGasLimit: 200_000,
			FinalityConfig:    tc.finalityConfig,
			Executor:          tc.executor,
		},
		3,
	)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	if len(sendRes.ReceiptIssuers) != tc.numExpectedRecv {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedRecv, len(sendRes.ReceiptIssuers))
	}

	sentEvt, err := tc.src.ConfirmSendOnSource(ctx, tc.dst.ChainSelector(), cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("wait for sent event: %w", err)
	}
	msgID := sentEvt.MessageID

	aggregatorClient := tc.deps.AggregatorClients[common.DefaultCommitteeVerifierQualifier]
	chainMap := tc.deps.ChainMap

	offchain := aggregatorClient != nil || tc.deps.IndexerMonitor != nil
	if offchain {
		testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, tc.deps.IndexerMonitor)
		defer cleanupFn()

		res, err := testCtx.AssertMessage(msgID, tcapi.AssertMessageOptions{
			TickInterval:            1 * time.Second,
			Timeout:                 tokenTransferExecTimeout,
			ExpectedVerifierResults: tc.numExpectedVer,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		})
		if err != nil {
			return fmt.Errorf("assert message: %w", err)
		}
		if aggregatorClient != nil && res.AggregatedResult == nil {
			return fmt.Errorf("aggregated result is nil")
		}
		if tc.deps.IndexerMonitor != nil && len(res.IndexedVerifications.Results) != tc.numExpectedVer {
			return fmt.Errorf("expected %d indexed verifications, got %d", tc.numExpectedVer, len(res.IndexedVerifications.Results))
		}
	} else {
		l.Info().Msg("skipping aggregator/indexer assertions (off-chain clients not configured)")
	}

	destChain := chainMap[tc.dst.ChainSelector()]
	execEvt, err := destChain.ConfirmExecOnDest(ctx, tc.src.ChainSelector(), cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tokenTransferExecTimeout)
	if err != nil {
		return fmt.Errorf("wait for exec event: %w", err)
	}
	if execEvt.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("unexpected execution state %s, return data: %x", execEvt.State, execEvt.ReturnData)
	}

	endBal, err := tc.dst.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver end balance: %w", err)
	}
	expectedEndBal := new(big.Int).Add(new(big.Int).Set(startBal), big.NewInt(tokenTransferAmount))
	if endBal.Cmp(expectedEndBal) != 0 {
		return fmt.Errorf("receiver end balance: expected %s, got %s", expectedEndBal.String(), endBal.String())
	}
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver end balance")

	srcEndBal, err := tc.src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender end balance: %w", err)
	}
	expectedSrcEndBal := new(big.Int).Sub(new(big.Int).Set(srcStartBal), big.NewInt(tokenTransferAmount))
	if srcEndBal.Cmp(expectedSrcEndBal) != 0 {
		return fmt.Errorf("sender end balance: expected %s, got %s", expectedSrcEndBal.String(), srcEndBal.String())
	}
	l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sender end balance")

	return nil
}

func (tc *tokenTransferV3TestCase) HavePrerequisites(ctx context.Context) bool {
	return tc.hydrate(ctx, tc)
}

// TokenTransfer returns a single token transfer test case for the given combo, finality, receiver type, and name.
func TokenTransfer(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string) tcapi.TestCase {
	return tokenTransferCase(src, dest, deps, combo, finalityConfig, useEOAReceiver, name)
}

func tokenTransferCase(src, dest cciptestinterfaces.CCIP17, deps *tcapi.CaseDeps, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string) *tokenTransferV3TestCase {
	return &tokenTransferV3TestCase{
		deps: deps,
		tokenTransferV3TestCaseBase: tokenTransferV3TestCaseBase{
			name:            name,
			src:             src,
			dst:             dest,
			combo:           combo,
			finalityConfig:  finalityConfig,
			useEOAReceiver:  useEOAReceiver,
			numExpectedRecv: combo.ExpectedReceiptIssuers(),
			numExpectedVer:  combo.ExpectedVerifierResults(),
		},
		hydrate: func(ctx context.Context, tc *tokenTransferV3TestCase) bool {
			sender, err := tc.src.GetSenderAddress()
			if err != nil {
				return false
			}
			tc.sender = sender

			if tc.useEOAReceiver {
				tc.receiver, err = tc.dst.GetEOAReceiverAddress()
			} else {
				var r tcapi.AddressResolver
				r, err = tc.deps.ResolverAt(tc.dst.ChainSelector())
				if err != nil {
					return false
				}
				tc.receiver, err = r.GetContractReceiver(tc.deps.DataStore, tc.dst.ChainSelector(), common.DefaultReceiverQualifier)
			}
			if err != nil {
				return false
			}

			srcQualifier := tc.combo.LocalPoolAddressRef().Qualifier
			rSrc, err := tc.deps.ResolverAt(tc.src.ChainSelector())
			if err != nil {
				return false
			}
			tc.srcToken, err = rSrc.GetBurnMintERC20(tc.deps.DataStore, tc.src.ChainSelector(), srcQualifier)
			if err != nil {
				return false
			}
			destQualifier := tc.combo.RemotePoolAddressRef().Qualifier
			rDst, err := tc.deps.ResolverAt(tc.dst.ChainSelector())
			if err != nil {
				return false
			}
			tc.destToken, err = rDst.GetBurnMintERC20(tc.deps.DataStore, tc.dst.ChainSelector(), destQualifier)
			if err != nil {
				return false
			}

			rExec, err := tc.deps.ResolverAt(tc.src.ChainSelector())
			if err != nil {
				return false
			}
			tc.executor, err = rExec.GetExecutor(tc.deps.DataStore, tc.src.ChainSelector(), common.DefaultExecutorQualifier)
			return err == nil
		},
	}
}

// All returns test cases for the given token combinations with EOA receiver and combo finality.
func All(ctx context.Context, env *deployment.Environment, addressResolvers tcapi.AddressResolvers, combos []common.TokenCombination, opts ...tcapi.CaseOption) ([]tcapi.TestCase, error) {
	deps, err := tcapi.BuildCaseDeps(ctx, env, addressResolvers, opts...)
	if err != nil {
		return nil, err
	}
	src := deps.ChainMap[deps.SrcSelector]
	dst := deps.ChainMap[deps.DstSelector]
	out := make([]tcapi.TestCase, 0, len(combos))
	for _, combo := range combos {
		name := fmt.Sprintf("token transfer EOA (%s)", combo.LocalPoolAddressRef().Qualifier)
		out = append(out, tokenTransferCase(src, dst, deps, combo, combo.FinalityConfig(), true, name))
	}
	return out, nil
}

// All17 returns test cases for 2.0.0-only token combinations: EOA and mock receiver with default finality (0).
func All17(ctx context.Context, env *deployment.Environment, addressResolvers tcapi.AddressResolvers, combos []common.TokenCombination, opts ...tcapi.CaseOption) ([]tcapi.TestCase, error) {
	deps, err := tcapi.BuildCaseDeps(ctx, env, addressResolvers, opts...)
	if err != nil {
		return nil, err
	}
	src := deps.ChainMap[deps.SrcSelector]
	dst := deps.ChainMap[deps.DstSelector]
	var filtered []common.TokenCombination
	for _, tc := range combos {
		if common.Is17Combination(tc) {
			filtered = append(filtered, tc)
		}
	}
	out := make([]tcapi.TestCase, 0, len(filtered)*2)
	for _, combo := range filtered {
		qual := combo.LocalPoolAddressRef().Qualifier
		out = append(out,
			tokenTransferCase(src, dst, deps, combo, 0, true, fmt.Sprintf("token transfer 1.7.0 EOA default finality (%s)", qual)),
			tokenTransferCase(src, dst, deps, combo, 0, false, fmt.Sprintf("token transfer 1.7.0 mock receiver default finality (%s)", qual)),
		)
	}
	return out, nil
}
