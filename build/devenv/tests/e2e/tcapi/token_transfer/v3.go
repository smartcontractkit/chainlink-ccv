package token_transfer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const tokenTransferAmount = 1000

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
	args            Args
}

type tokenTransferV3TestCase struct {
	tokenTransferV3TestCaseBase
	sender    protocol.UnknownAddress
	receiver  protocol.UnknownAddress
	srcToken  protocol.UnknownAddress
	destToken protocol.UnknownAddress
	executor  protocol.UnknownAddress
	hydrate   func(ctx context.Context, tc *tokenTransferV3TestCase) bool
	hydrated  bool
}

func (tc *tokenTransferV3TestCase) Name() string {
	return tc.name
}

func (tc *tokenTransferV3TestCase) ensureHydrated(ctx context.Context) error {
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

func (tc *tokenTransferV3TestCase) Run(ctx context.Context) error {
	if err := tc.ensureHydrated(ctx); err != nil {
		return err
	}
	l := zerolog.Ctx(ctx)
	v3Src, err := tc.lib.V3Source(ctx, tc.src)
	if err != nil {
		return fmt.Errorf("source chain %d does not support V3 message: %w", tc.src, err)
	}
	v3Dst, err := tc.lib.V3Destination(ctx, tc.dst)
	if err != nil {
		return fmt.Errorf("destination chain %d does not support V3 message: %w", tc.dst, err)
	}
	srcBalReader, ok := v3Src.(cciptestinterfaces.TokenBalanceReader)
	if !ok {
		return fmt.Errorf("source chain %d does not support token balance reads", tc.src)
	}
	dstBalReader, ok := v3Dst.(cciptestinterfaces.TokenBalanceReader)
	if !ok {
		return fmt.Errorf("destination chain %d does not support token balance reads", tc.dst)
	}

	startBal, err := dstBalReader.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver start balance: %w", err)
	}
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver start balance")

	srcStartBal, err := srcBalReader.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender start balance: %w", err)
	}
	l.Info().Str("Sender", tc.sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sender start balance")

	transferAmount := big.NewInt(tokenTransferAmount)
	if tc.args.TransferAmount != nil {
		transferAmount = tc.args.TransferAmount
	}
	destIncrease := transferAmount
	if tc.args.DestBalanceIncrease != nil {
		destIncrease = tc.args.DestBalanceIncrease
	}
	sentTimeout := tc.args.Run.SentTimeout(tcapi.DefaultSentTimeout)
	execTimeout := tc.args.Run.ExecTimeout(tcapi.DefaultExecTimeout)
	msgReceiver := tc.receiver
	if tc.args.Send.TokenReceiverParams != nil {
		msgReceiver = make([]byte, len(tc.receiver))
	}

	sendRes, err := tcapi.SendV3Message(ctx, v3Src, v3Dst, tc.dst,
		cciptestinterfaces.MessageFields{
			Receiver: msgReceiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       transferAmount,
				TokenAddress: tc.srcToken,
			},
		},
		cciptestinterfaces.MessageOptions{
			FinalityConfig: tc.finalityConfig,
			Executor:       tc.executor,
		},
		tc.args.Send,
	)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	if len(sendRes.ReceiptIssuers) != tc.numExpectedRecv {
		return fmt.Errorf("expected %d receipt issuers, got %d", tc.numExpectedRecv, len(sendRes.ReceiptIssuers))
	}
	if sendRes.MessageID == (protocol.Bytes32{}) {
		return fmt.Errorf("send returned zero message ID")
	}
	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sendRes.MessageID}
	if sendRes.Message != nil {
		l.Info().Uint64("SeqNo", uint64(sendRes.Message.SequenceNumber)).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sent message")
	}
	_, err = v3Src.ConfirmSendOnSource(ctx, tc.dst, messageKey, sentTimeout)
	if err != nil {
		return fmt.Errorf("wait for sent event: %w", err)
	}
	msgID := sendRes.MessageID

	aggregatorClient, indexerMonitor, err := tcapi.SetupOffchainClients(tc.lib, "")
	if err != nil {
		return err
	}
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, aggregatorClient, indexerMonitor)
	defer cleanupFn()

	res, err := testCtx.AssertMessage(msgID, tcapi.AssertMessageOptions{
		TickInterval:            1 * time.Second,
		Timeout:                 execTimeout,
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

	execEvt, err := v3Dst.ConfirmExecOnDest(ctx, tc.src, messageKey, execTimeout)
	if err != nil {
		return fmt.Errorf("wait for exec event: %w", err)
	}
	if execEvt.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("unexpected execution state %s, return data: %x", execEvt.State, execEvt.ReturnData)
	}

	endBal, err := dstBalReader.GetTokenBalance(ctx, tc.receiver, tc.destToken)
	if err != nil {
		return fmt.Errorf("get receiver end balance: %w", err)
	}
	expectedEndBal := new(big.Int).Add(new(big.Int).Set(startBal), destIncrease)
	if endBal.Cmp(expectedEndBal) != 0 {
		return fmt.Errorf("receiver end balance: expected %s, got %s", expectedEndBal.String(), endBal.String())
	}
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver end balance")

	srcEndBal, err := srcBalReader.GetTokenBalance(ctx, tc.sender, tc.srcToken)
	if err != nil {
		return fmt.Errorf("get sender end balance: %w", err)
	}
	expectedSrcEndBal := new(big.Int).Sub(new(big.Int).Set(srcStartBal), transferAmount)
	if srcEndBal.Cmp(expectedSrcEndBal) != 0 {
		return fmt.Errorf("sender end balance: expected %s, got %s", expectedSrcEndBal.String(), srcEndBal.String())
	}
	l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", tc.combo.LocalPoolAddressRef().Qualifier).Msg("sender end balance")

	return nil
}

func (tc *tokenTransferV3TestCase) HavePrerequisites(ctx context.Context) bool {
	return tc.ensureHydrated(ctx) == nil
}

// TokenTransfer returns a single token transfer test case for the given combo, finality, receiver type, and name.
func TokenTransfer(lib ccv.Lib, src, dest uint64, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string, args Args) tcapi.TestCase {
	return tokenTransferCase(lib, src, dest, combo, finalityConfig, useEOAReceiver, name, args)
}

func tokenTransferCase(lib ccv.Lib, src, dest uint64, combo common.TokenCombination, finalityConfig protocol.Finality, useEOAReceiver bool, name string, args Args) *tokenTransferV3TestCase {
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
			args:            args,
		},
		hydrate: func(ctx context.Context, tc *tokenTransferV3TestCase) bool {
			srcFamily, err := chain_selectors.GetSelectorFamily(tc.src)
			if err != nil {
				return false
			}
			srcReg, err := chainreg.GetRegistry().Get(srcFamily)
			if err != nil {
				return false
			}
			dstFamily, err := chain_selectors.GetSelectorFamily(tc.dst)
			if err != nil {
				return false
			}
			dstReg, err := chainreg.GetRegistry().Get(dstFamily)
			if err != nil {
				return false
			}
			if srcReg.AddressResolver == nil || dstReg.AddressResolver == nil {
				return false
			}
			ds, err := tc.lib.DataStore()
			if err != nil {
				return false
			}
			v3Src, err := tc.lib.V3Source(ctx, tc.src)
			if err != nil {
				return false
			}
			senderProvider, ok := v3Src.(cciptestinterfaces.SenderAddressProvider)
			if !ok {
				return false
			}
			sender, err := senderProvider.GetSenderAddress()
			if err != nil {
				return false
			}
			tc.sender = sender

			if tc.useEOAReceiver {
				v3Dst, dstErr := tc.lib.V3Destination(ctx, tc.dst)
				if dstErr != nil {
					return false
				}
				tc.receiver, err = v3Dst.GetEOAReceiverAddress()
			} else {
				tc.receiver, err = dstReg.AddressResolver.GetContractReceiver(ds, tc.dst, common.DefaultReceiverQualifier)
			}
			if err != nil {
				return false
			}

			tc.srcToken, err = srcReg.AddressResolver.GetToken(ds, tc.src, tc.combo.LocalPoolAddressRef())
			if err != nil {
				return false
			}
			tc.destToken, err = dstReg.AddressResolver.GetToken(ds, tc.dst, tc.combo.RemotePoolAddressRef())
			if err != nil {
				return false
			}

			tc.executor, err = srcReg.AddressResolver.GetExecutor(ds, tc.src, common.DefaultExecutorQualifier)
			return err == nil
		},
	}
}

// All returns test cases for the given token combinations with EOA receiver and combo finality.
func All(lib ccv.Lib, src, dest uint64, combos []common.TokenCombination, args Args) []tcapi.TestCase {
	out := make([]tcapi.TestCase, 0, len(combos))
	for _, combo := range combos {
		name := fmt.Sprintf("token transfer EOA (%s)", combo.LocalPoolAddressRef().Qualifier)
		out = append(out, tokenTransferCase(lib, src, dest, combo, combo.FinalityConfig(), true, name, args))
	}
	return out
}

// All17 returns test cases for 2.0.0-only token combinations: EOA and mock receiver with default finality (0).
func All17(lib ccv.Lib, src, dest uint64, combos []common.TokenCombination, args Args) []tcapi.TestCase {
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
			tokenTransferCase(lib, src, dest, combo, 0, true, fmt.Sprintf("token transfer 1.7.0 EOA default finality (%s)", qual), args),
			tokenTransferCase(lib, src, dest, combo, 0, false, fmt.Sprintf("token transfer 1.7.0 mock receiver default finality (%s)", qual), args),
		)
	}
	return out
}
