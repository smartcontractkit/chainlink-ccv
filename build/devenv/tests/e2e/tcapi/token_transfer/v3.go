package token_transfer

import (
	"context"
	"errors"
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
	hydrate   func(ctx context.Context, tc *tokenTransferV3TestCase) ([]tcapi.MissingPrerequisite, error)
	hydrated  bool
}

func (tc *tokenTransferV3TestCase) Name() string {
	return tc.name
}

func (tc *tokenTransferV3TestCase) ensureHydrated(ctx context.Context) ([]tcapi.MissingPrerequisite, error) {
	if tc.hydrated {
		return nil, nil
	}
	if tc.hydrate == nil {
		return nil, fmt.Errorf("%s: missing hydrate func", tc.name)
	}
	missing, err := tc.hydrate(ctx, tc)
	if err != nil {
		return nil, err
	}
	if len(missing) == 0 {
		tc.hydrated = true
	}
	return missing, nil
}

func (tc *tokenTransferV3TestCase) Run(ctx context.Context) error {
	missing, err := tc.ensureHydrated(ctx)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		errs := make([]error, len(missing))
		for i, m := range missing {
			errs[i] = m
		}
		return errors.Join(errs...)
	}
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

	sendRes, err := tcapi.SendV3Message(ctx, src, dst, tc.dst,
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
	_, err = src.ConfirmSendOnSource(ctx, tc.dst, messageKey, sentTimeout)
	if err != nil {
		return fmt.Errorf("wait for sent event: %w", err)
	}
	msgID := sendRes.MessageID

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
		Timeout:                 execTimeout,
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

	execEvt, err := dst.ConfirmExecOnDest(ctx, tc.src, messageKey, execTimeout)
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
	expectedEndBal := new(big.Int).Add(new(big.Int).Set(startBal), destIncrease)
	if endBal.Cmp(expectedEndBal) != 0 {
		return fmt.Errorf("receiver end balance: expected %s, got %s", expectedEndBal.String(), endBal.String())
	}
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", tc.combo.RemotePoolAddressRef().Qualifier).Msg("receiver end balance")

	srcEndBal, err := src.GetTokenBalance(ctx, tc.sender, tc.srcToken)
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

func (tc *tokenTransferV3TestCase) CheckPrerequisites(ctx context.Context) ([]tcapi.MissingPrerequisite, error) {
	return tc.ensureHydrated(ctx)
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
		hydrate: func(ctx context.Context, tc *tokenTransferV3TestCase) ([]tcapi.MissingPrerequisite, error) {
			srcFamily, err := chain_selectors.GetSelectorFamily(tc.src)
			if err != nil {
				return nil, fmt.Errorf("source chain family: %w", err)
			}
			srcReg, err := chainreg.GetRegistry().Get(srcFamily)
			if err != nil {
				return nil, fmt.Errorf("source chain registry: %w", err)
			}
			dstFamily, err := chain_selectors.GetSelectorFamily(tc.dst)
			if err != nil {
				return nil, fmt.Errorf("dest chain family: %w", err)
			}
			dstReg, err := chainreg.GetRegistry().Get(dstFamily)
			if err != nil {
				return nil, fmt.Errorf("dest chain registry: %w", err)
			}
			if srcReg.AddressResolver == nil || dstReg.AddressResolver == nil {
				return nil, fmt.Errorf("missing address resolver")
			}
			ds, err := tc.lib.DataStore()
			if err != nil {
				return nil, fmt.Errorf("data store: %w", err)
			}
			chainMap, err := tc.lib.ChainsMap(ctx)
			if err != nil {
				return nil, fmt.Errorf("chains map: %w", err)
			}
			src, ok := chainMap[tc.src]
			if !ok {
				return nil, fmt.Errorf("chain %d not found in chains map", tc.src)
			}
			dst, ok := chainMap[tc.dst]
			if !ok {
				return nil, fmt.Errorf("chain %d not found in chains map", tc.dst)
			}
			sender, err := src.GetSenderAddress()
			if err != nil {
				return nil, fmt.Errorf("sender address: %w", err)
			}
			tc.sender = sender

			var missing []tcapi.MissingPrerequisite

			var receiverName string
			var receiver protocol.UnknownAddress
			var receiverErr error
			if tc.useEOAReceiver {
				receiver, receiverErr = dst.GetEOAReceiverAddress()
				receiverName = "EOA receiver address"
			} else {
				receiver, receiverErr = dstReg.AddressResolver.GetContractReceiver(ds, tc.dst, common.DefaultReceiverQualifier)
				receiverName = "contract receiver (default)"
			}
			if receiverErr != nil {
				missing = append(missing, tcapi.MissingPrerequisite{Name: receiverName, Err: receiverErr})
			} else {
				tc.receiver = receiver
			}

			srcToken, err := srcReg.AddressResolver.GetToken(ds, tc.src, tc.combo.LocalPoolAddressRef())
			if err != nil {
				missing = append(missing, tcapi.MissingPrerequisite{Name: fmt.Sprintf("source token (%s)", tc.combo.LocalPoolAddressRef().Qualifier), Err: err})
			} else {
				tc.srcToken = srcToken
			}

			destToken, err := dstReg.AddressResolver.GetToken(ds, tc.dst, tc.combo.RemotePoolAddressRef())
			if err != nil {
				missing = append(missing, tcapi.MissingPrerequisite{Name: fmt.Sprintf("dest token (%s)", tc.combo.RemotePoolAddressRef().Qualifier), Err: err})
			} else {
				tc.destToken = destToken
			}

			executor, err := srcReg.AddressResolver.GetExecutor(ds, tc.src, common.DefaultExecutorQualifier)
			if err != nil {
				missing = append(missing, tcapi.MissingPrerequisite{Name: "executor (default)", Err: err})
			} else {
				tc.executor = executor
			}

			return missing, nil
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
