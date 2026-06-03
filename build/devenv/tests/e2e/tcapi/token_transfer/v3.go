package token_transfer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
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
	lib             ccv.Lib
	name            string
	src             uint64
	dst             uint64
	combo           common.TokenCombination
	finalityConfig  protocol.Finality
	useEOAReceiver  bool
	numExpectedRecv int
	numExpectedVer  int
	sendConfig      tcapi.SendConfig
}

type tokenTransferV3TestCase struct {
	tokenTransferV3TestCaseBase
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
	chainMap, err := tc.lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("get chains map: %w", err)
	}
	src, ok := chainMap[tc.src]
	if !ok {
		return fmt.Errorf("chain %d not found", tc.src)
	}
	dst, ok := chainMap[tc.dst]
	if !ok {
		return fmt.Errorf("chain %d not found", tc.dst)
	}
	startBal, err := dst.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver start balance: %w", err)
	}
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver start balance")

	srcStartBal, err := src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender start balance: %w", err)
	}
	l.Info().Str("Sender", tc.sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sender start balance")

	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, tc.dst)
	if err != nil {
		return fmt.Errorf("get expected next sequence number: %w", err)
	}
	l.Info().Uint64("SeqNo", seqNo).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("expecting sequence number")

	sendRes, err := tcapi.SendV3Message(ctx, src, dst, tc.dst,
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       big.NewInt(tokenTransferAmount),
				TokenAddress: tc.srcToken,
			},
		},
		cciptestinterfaces.MessageOptions{
			FinalityConfig: tc.finalityConfig,
			Executor:       tc.executor,
		},
		tc.sendConfig,
	)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	if len(sendRes.ReceiptIssuers) != tc.numExpectedRecv {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedRecv, len(sendRes.ReceiptIssuers))
	}

	sentEvt, err := src.ConfirmSendOnSource(ctx, tc.dst, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultSentTimeout)
	if err != nil {
		return fmt.Errorf("wait for sent event: %w", err)
	}
	msgID := sentEvt.MessageID

	aggregatorClients, err := tc.lib.AllAggregators()
	if err != nil {
		return fmt.Errorf("failed to get aggregator clients: %w", err)
	}
	aggregatorClient := aggregatorClients[common.DefaultCommitteeVerifierQualifier]
	indexerMonitor, err := tc.lib.IndexerMonitor()
	if err != nil {
		return fmt.Errorf("failed to get indexer monitor: %w", err)
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, indexerMonitor)
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

	execEvt, err := dst.ConfirmExecOnDest(ctx, tc.src, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tokenTransferExecTimeout)
	if err != nil {
		return fmt.Errorf("wait for exec event: %w", err)
	}
	if execEvt.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("unexpected execution state %s, return data: %x", execEvt.State, execEvt.ReturnData)
	}

	endBal, err := dst.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver end balance: %w", err)
	}
	expectedEndBal := new(big.Int).Add(new(big.Int).Set(startBal), big.NewInt(tokenTransferAmount))
	if endBal.Cmp(expectedEndBal) != 0 {
		return fmt.Errorf("receiver end balance: expected %s, got %s", expectedEndBal.String(), endBal.String())
	}
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver end balance")

	srcEndBal, err := src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
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

func getTokenAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
	return tcapi.GetContractAddress(ds, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
		burn_mint_erc20_with_drip.Deploy.Version(),
		qualifier,
		"burn mint erc677")
}

// TokenTransfer returns a single token transfer test case for the given combo, finality, receiver type, and name.
func TokenTransfer(lib ccv.Lib, src, dest uint64, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string, cfg tcapi.SendConfig) tcapi.TestCase {
	return tokenTransferCase(lib, src, dest, combo, finalityConfig, useEOAReceiver, name, cfg)
}

func tokenTransferCase(lib ccv.Lib, src, dest uint64, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string, cfg tcapi.SendConfig) *tokenTransferV3TestCase {
	return &tokenTransferV3TestCase{
		tokenTransferV3TestCaseBase: tokenTransferV3TestCaseBase{
			name:            name,
			lib:             lib,
			src:             src,
			dst:             dest,
			combo:           combo,
			finalityConfig:  finalityConfig,
			useEOAReceiver:  useEOAReceiver,
			numExpectedRecv: combo.ExpectedReceiptIssuers(),
			numExpectedVer:  combo.ExpectedVerifierResults(),
			sendConfig:      cfg,
		},
		hydrate: func(ctx context.Context, tc *tokenTransferV3TestCase) bool {
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return false
			}
			src, ok := chainMap[tc.src]
			if !ok {
				return false
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return false
			}
			sender, err := src.GetSenderAddress()
			if err != nil {
				return false
			}
			tc.sender = sender

			if tc.useEOAReceiver {
				tc.receiver, err = dst.GetEOAReceiverAddress()
			} else {
				tc.receiver, err = tcapi.GetContractAddress(ds, tc.dst, datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(), common.DefaultReceiverQualifier, "default mock receiver")
			}
			if err != nil {
				return false
			}

			srcQualifier := tc.combo.LocalPoolAddressRef().Qualifier
			tc.srcToken, err = getTokenAddress(ds, tc.src, srcQualifier)
			if err != nil {
				return false
			}
			destQualifier := tc.combo.RemotePoolAddressRef().Qualifier
			tc.destToken, err = getTokenAddress(ds, tc.dst, destQualifier)
			if err != nil {
				return false
			}

			tc.executor, err = tcapi.GetContractAddress(ds, tc.src, datastore.ContractType(sequences.ExecutorProxyType), proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor")
			return err == nil
		},
	}
}

// All returns test cases for the given token combinations with EOA receiver and combo finality.
func All(lib ccv.Lib, src, dest uint64, combos []common.TokenCombination, cfg tcapi.SendConfig) []tcapi.TestCase {
	out := make([]tcapi.TestCase, 0, len(combos))
	for _, combo := range combos {
		name := fmt.Sprintf("token transfer EOA (%s)", combo.LocalPoolAddressRef().Qualifier)
		out = append(out, tokenTransferCase(lib, src, dest, combo, combo.FinalityConfig(), true, name, cfg))
	}
	return out
}

// All17 returns test cases for 2.0.0-only token combinations: EOA and mock receiver with default finality (0).
func All17(lib ccv.Lib, src, dest uint64, combos []common.TokenCombination, cfg tcapi.SendConfig) []tcapi.TestCase {
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
			tokenTransferCase(lib, src, dest, combo, 0, true, fmt.Sprintf("token transfer 1.7.0 EOA default finality (%s)", qual), cfg),
			tokenTransferCase(lib, src, dest, combo, 0, false, fmt.Sprintf("token transfer 1.7.0 mock receiver default finality (%s)", qual), cfg),
		)
	}
	return out
}
