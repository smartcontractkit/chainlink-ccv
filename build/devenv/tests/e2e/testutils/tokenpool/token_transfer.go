package tokenpool

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var addrNormRegistry = deploy.GetAddressNormalizerRegistry()

const (
	legacyExpectedReceiptIssuers  = 4
	legacyExpectedVerifierResults = 1
)

func RunBidirectionalTokenTransfer(t *testing.T, lib ccv.Lib, poolA, poolB TokenPool, amount int64, finality protocol.Finality, phase string) {
	t.Helper()

	t.Run(phase+" transfer A→B", func(t *testing.T) {
		transferTokens(t, lib, poolA, poolB, amount, finality)
	})

	t.Run(phase+" transfer B→A", func(t *testing.T) {
		transferTokens(t, lib, poolB, poolA, amount, finality)
	})
}

func transferTokens(
	t *testing.T,
	lib ccv.Lib,
	srcPool, dstPool TokenPool,
	amount int64,
	finality protocol.Finality,
) {
	t.Helper()

	ds, err := lib.DataStore()
	require.NoError(t, err, "get datastore")

	srcSel := srcPool.Selector()
	srcTok := srcPool.Token()
	srcFamily, err := chainsel.GetSelectorFamily(srcSel)
	require.NoError(t, err, "get source chain family")
	srcNorm, ok := addrNormRegistry.GetAddressNormalizer(srcFamily)
	require.True(t, ok, "no address normalizer for source chain family %s", srcFamily)
	srcTokenBytes, err := srcNorm.StringToBytes(srcTok)
	require.NoError(t, err, "normalize source token address")
	srcTokenAddr := protocol.UnknownAddress(srcTokenBytes)

	dstSel := dstPool.Selector()
	dstTok := dstPool.Token()
	dstFamily, err := chainsel.GetSelectorFamily(dstSel)
	require.NoError(t, err, "get destination chain family")
	dstNorm, ok := addrNormRegistry.GetAddressNormalizer(dstFamily)
	require.True(t, ok, "no address normalizer for destination chain family %s", dstFamily)
	dstTokenBytes, err := dstNorm.StringToBytes(dstTok)
	require.NoError(t, err, "normalize destination token address")
	dstTokenAddr := protocol.UnknownAddress(dstTokenBytes)

	v3Src, err := lib.V3Source(t.Context(), srcSel)
	require.NoError(t, err, "source chain %d does not support V3 message", srcSel)
	v3Dst, err := lib.V3Destination(t.Context(), dstSel)
	require.NoError(t, err, "destination chain %d does not support V3 message", dstSel)

	senderProvider, ok := v3Src.(cciptestinterfaces.SenderAddressProvider)
	require.True(t, ok, "source chain %d does not support sender address", srcSel)
	sender, err := senderProvider.GetSenderAddress()
	require.NoError(t, err, "get sender address")

	receiver, err := v3Dst.GetEOAReceiverAddress()
	require.NoError(t, err, "get receiver address")

	srcReg, err := chainreg.GetRegistry().Get(srcFamily)
	require.NoError(t, err, "get source chain registry")
	require.NotNil(t, srcReg.AddressResolver, "source chain registry has no address resolver")
	executor, err := srcReg.AddressResolver.GetExecutor(ds, srcSel, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err, "get executor address")

	srcBalReader, ok := v3Src.(cciptestinterfaces.TokenBalanceReader)
	require.True(t, ok, "source chain %d does not support token balance reads", srcSel)
	dstBalReader, ok := v3Dst.(cciptestinterfaces.TokenBalanceReader)
	require.True(t, ok, "destination chain %d does not support token balance reads", dstSel)

	dstStartBal, err := dstBalReader.GetTokenBalance(t.Context(), receiver, dstTokenAddr)
	require.NoError(t, err, "get receiver start balance")

	srcStartBal, err := srcBalReader.GetTokenBalance(t.Context(), sender, srcTokenAddr)
	require.NoError(t, err, "get sender start balance")

	amountToTransfer := tokens.ScaleTokenAmount(big.NewInt(amount), srcPool.Decimals())
	require.NoError(t, tcapi.RunV3MessageLifecycle(t.Context(), lib, tcapi.V3MsgConifg{
		Src: srcSel,
		Dst: dstSel,
		Fields: cciptestinterfaces.MessageFields{
			Receiver: receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       amountToTransfer,
				TokenAddress: srcTokenAddr,
			},
		},
		Opts: cciptestinterfaces.MessageOptions{
			FinalityConfig: finality,
			Executor:       executor,
		},
		SendArgs: tcapi.SendArgs{},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            time.Second,
			Timeout:                 tcapi.DefaultExecTimeout,
			ExpectedVerifierResults: legacyExpectedVerifierResults,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
		ExecTimeout:            tcapi.DefaultExecTimeout,
		ExpectedReceiptIssuers: legacyExpectedReceiptIssuers,
		ConfirmExec:            true,
	}))

	dstEndBal, err := dstBalReader.GetTokenBalance(t.Context(), receiver, dstTokenAddr)
	require.NoError(t, err, "get receiver end balance")
	expectedEndBal := new(big.Int).Add(new(big.Int).Set(dstStartBal), amountToTransfer)
	require.Equal(t, 0, dstEndBal.Cmp(expectedEndBal), "receiver end balance: expected %s, got %s", expectedEndBal.String(), dstEndBal.String())

	srcEndBal, err := srcBalReader.GetTokenBalance(t.Context(), sender, srcTokenAddr)
	require.NoError(t, err, "get sender end balance")
	expectedSrcEndBal := new(big.Int).Sub(new(big.Int).Set(srcStartBal), amountToTransfer)
	require.Equal(t, 0, srcEndBal.Cmp(expectedSrcEndBal), "sender end balance: expected %s, got %s", expectedSrcEndBal.String(), srcEndBal.String())
}
