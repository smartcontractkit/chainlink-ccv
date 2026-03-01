package token_transfer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
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
	finalityConfig  uint16
	useEOAReceiver  bool
	numExpectedRecv int
	numExpectedVer  int
}

type tokenTransferV3TestCase struct {
	tokenTransferV3TestCaseBase
	sender    protocol.UnknownAddress
	receiver  protocol.UnknownAddress
	srcToken  protocol.UnknownAddress
	destToken protocol.UnknownAddress
	executor  protocol.UnknownAddress
	hydrate   func(ctx context.Context, tc *tokenTransferV3TestCase, cfg *ccv.Cfg) bool
}

func (tc *tokenTransferV3TestCase) Name() string {
	return tc.name
}

func (tc *tokenTransferV3TestCase) Run(ctx context.Context, harness tcapi.TestHarness, cfg *ccv.Cfg) error {
	l := zerolog.Ctx(ctx)
	startBal, err := tc.dst.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver start balance: %w", err)
	}
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", tc.combo.DestPoolAddressRef().Qualifier).Msg("receiver start balance")

	srcStartBal, err := tc.src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender start balance: %w", err)
	}
	l.Info().Str("Sender", tc.sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", tc.combo.SourcePoolAddressRef().Qualifier).Msg("sender start balance")

	seqNo, err := tc.src.GetExpectedNextSequenceNumber(ctx, tc.dst.ChainSelector())
	if err != nil {
		return fmt.Errorf("get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Str("Token", tc.combo.SourcePoolAddressRef().Qualifier).Msg("expecting sequence number")

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
			Version:           3,
			ExecutionGasLimit: 200_000,
			FinalityConfig:    tc.finalityConfig,
			Executor:          tc.executor,
		},
	)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	if len(sendRes.ReceiptIssuers) != tc.numExpectedRecv {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedRecv, len(sendRes.ReceiptIssuers))
	}

	sentEvt, err := tc.src.WaitOneSentEventBySeqNo(ctx, tc.dst.ChainSelector(), seqNo, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("wait for sent event: %w", err)
	}
	msgID := sentEvt.MessageID

	aggregatorClient := harness.AggregatorClients[common.DefaultCommitteeVerifierQualifier]
	chainMap, err := harness.Lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("get chains map: %w", err)
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, harness.IndexerMonitor)
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
	if res.AggregatedResult == nil {
		return fmt.Errorf("aggregated result is nil")
	}

	destChain := chainMap[tc.dst.ChainSelector()]
	execEvt, err := destChain.WaitOneExecEventBySeqNo(ctx, tc.src.ChainSelector(), seqNo, tokenTransferExecTimeout)
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
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", tc.combo.DestPoolAddressRef().Qualifier).Msg("receiver end balance")

	srcEndBal, err := tc.src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender end balance: %w", err)
	}
	expectedSrcEndBal := new(big.Int).Sub(new(big.Int).Set(srcStartBal), big.NewInt(tokenTransferAmount))
	if srcEndBal.Cmp(expectedSrcEndBal) != 0 {
		return fmt.Errorf("sender end balance: expected %s, got %s", expectedSrcEndBal.String(), srcEndBal.String())
	}
	l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", tc.combo.SourcePoolAddressRef().Qualifier).Msg("sender end balance")

	return nil
}

func (tc *tokenTransferV3TestCase) HavePrerequisites(ctx context.Context, cfg *ccv.Cfg) bool {
	return tc.hydrate(ctx, tc, cfg)
}

func getTokenAddress(cfg *ccv.Cfg, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
	return tcapi.GetContractAddress(cfg, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
		burn_mint_erc20_with_drip.Deploy.Version(),
		qualifier,
		"burn mint erc677")
}

// TokenTransfer returns a single token transfer test case for the given combo, finality, receiver type, and name.
func TokenTransfer(src, dest cciptestinterfaces.CCIP17, combo common.TokenCombination, finalityConfig uint16, useEOAReceiver bool, name string) tcapi.TestCase {
	return tokenTransferCase(src, dest, combo, finalityConfig, useEOAReceiver, name)
}

func tokenTransferCase(src, dest cciptestinterfaces.CCIP17, combo common.TokenCombination, finalityConfig uint16, useEOAReceiver bool, name string) *tokenTransferV3TestCase {
	return &tokenTransferV3TestCase{
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
		hydrate: func(ctx context.Context, tc *tokenTransferV3TestCase, cfg *ccv.Cfg) bool {
			sender, err := tc.src.GetSenderAddress()
			if err != nil {
				return false
			}
			tc.sender = sender

			if tc.useEOAReceiver {
				tc.receiver, err = tc.dst.GetEOAReceiverAddress()
			} else {
				tc.receiver, err = tcapi.GetContractAddress(cfg, tc.dst.ChainSelector(), datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			}
			if err != nil {
				return false
			}

			srcQualifier := tc.combo.SourcePoolAddressRef().Qualifier
			tc.srcToken, err = getTokenAddress(cfg, tc.src.ChainSelector(), srcQualifier)
			if err != nil {
				return false
			}
			destQualifier := tc.combo.DestPoolAddressRef().Qualifier
			tc.destToken, err = getTokenAddress(cfg, tc.dst.ChainSelector(), destQualifier)
			if err != nil {
				return false
			}

			tc.executor, err = tcapi.GetContractAddress(cfg, tc.src.ChainSelector(), datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor")
			if err != nil {
				return false
			}
			return true
		},
	}
}

// All returns test cases for all token combinations with EOA receiver and combo finality.
func All(src, dest cciptestinterfaces.CCIP17) []tcapi.TestCase {
	out := make([]tcapi.TestCase, 0, len(common.AllTokenCombinations()))
	for _, combo := range common.AllTokenCombinations() {
		name := fmt.Sprintf("token transfer EOA (%s)", combo.SourcePoolAddressRef().Qualifier)
		out = append(out, tokenTransferCase(src, dest, combo, combo.FinalityConfig(), true, name))
	}
	return out
}

// All17 returns test cases for 1.7.0 token combinations: EOA and mock receiver with default finality (0).
func All17(src, dest cciptestinterfaces.CCIP17) []tcapi.TestCase {
	combos := common.All17TokenCombinations()
	out := make([]tcapi.TestCase, 0, len(combos)*2)
	for _, combo := range combos {
		qual := combo.SourcePoolAddressRef().Qualifier
		out = append(out,
			tokenTransferCase(src, dest, combo, 0, true, fmt.Sprintf("token transfer 1.7.0 EOA default finality (%s)", qual)),
			tokenTransferCase(src, dest, combo, 0, false, fmt.Sprintf("token transfer 1.7.0 mock receiver default finality (%s)", qual)),
		)
	}
	return out
}
