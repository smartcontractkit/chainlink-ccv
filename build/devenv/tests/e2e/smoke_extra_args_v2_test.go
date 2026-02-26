package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// v2TestCase is for tests that use ExtraArgsV2.
type v2TestCase struct {
	name                     string
	fromSelector             uint64
	toSelector               uint64
	receiver                 protocol.UnknownAddress
	expectFail               bool
	assertExecuted           bool
	numExpectedVerifications int
}

func TestE2ESmoke_ExtraArgsV2(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	// Only load EVM chains for now, as more chains become supported we can add them.
	lib, err := ccv.NewLib(l, smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	aggregatorClients := SetupAggregatorClients(t, ctx, in)
	defaultAggregatorClient := aggregatorClients[common.DefaultCommitteeVerifierQualifier]

	indexerMonitor := SetupIndexerMonitor(t, ctx, lib)

	sel0, sel1, sel2 := chains[0].Details.ChainSelector,
		chains[1].Details.ChainSelector,
		chains[2].Details.ChainSelector

	tcs := []v2TestCase{
		{
			name:                     "src->dst msg execution eoa receiver",
			fromSelector:             sel0,
			toSelector:               sel1,
			receiver:                 mustGetEOAReceiverAddress(t, chainMap[sel1]),
			expectFail:               false,
			numExpectedVerifications: 1,
		},
		{
			name:                     "dst->src msg execution eoa receiver",
			fromSelector:             sel1,
			toSelector:               sel0,
			receiver:                 mustGetEOAReceiverAddress(t, chainMap[sel0]),
			expectFail:               false,
			numExpectedVerifications: 1,
		},
		{
			name:                     "1337->3337 msg execution mock receiver",
			fromSelector:             sel0,
			toSelector:               sel2,
			receiver:                 getContractAddress(t, in, sel2, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), common.DefaultReceiverQualifier, "mock receiver"),
			expectFail:               false,
			numExpectedVerifications: 1,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			runV2TestCase(t, ctx, l, tc, chainMap, defaultAggregatorClient, indexerMonitor, AssertMessageOptions{
				TickInterval:            1 * time.Second,
				Timeout:                 defaultExecTimeout,
				ExpectedVerifierResults: tc.numExpectedVerifications,
				AssertVerifierLogs:      false,
				AssertExecutorLogs:      false,
			})
		})
	}
}

func runV2TestCase(
	t *testing.T,
	ctx context.Context,
	l *zerolog.Logger,
	tc v2TestCase,
	chainMap map[uint64]cciptestinterfaces.CCIP17,
	defaultAggregatorClient *ccv.AggregatorClient,
	indexerClient *ccv.IndexerMonitor,
	assertMessageOptions AssertMessageOptions,
) {
	seqNo, err := chainMap[tc.fromSelector].GetExpectedNextSequenceNumber(ctx, tc.toSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	_, err = chainMap[tc.fromSelector].SendMessage(ctx, tc.toSelector, cciptestinterfaces.MessageFields{
		Receiver: tc.receiver,
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:             2,
		ExecutionGasLimit:   200_000,
		OutOfOrderExecution: true,
	})
	require.NoError(t, err)

	sentEvent, err := chainMap[tc.fromSelector].WaitOneSentEventBySeqNo(ctx, tc.toSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	messageID := sentEvent.MessageID

	testCtx := NewTestingContext(t, ctx, chainMap, defaultAggregatorClient, indexerClient)
	result, err := testCtx.AssertMessage(messageID, assertMessageOptions)
	require.NoError(t, err)
	require.NotNil(t, result.AggregatedResult)
	require.Len(t, result.IndexedVerifications.Results, tc.numExpectedVerifications)

	if tc.assertExecuted {
		e, err := chainMap[tc.toSelector].WaitOneExecEventBySeqNo(ctx, tc.fromSelector, seqNo, defaultExecTimeout)
		require.NoError(t, err)
		require.NotNil(t, e)

		if tc.expectFail {
			require.Equalf(t,
				cciptestinterfaces.ExecutionStateFailure,
				e.State,
				"unexpected state, return data: %x",
				e.ReturnData)
		} else {
			require.Equalf(t,
				cciptestinterfaces.ExecutionStateSuccess,
				e.State,
				"unexpected state, return data: %x",
				e.ReturnData)
		}
	}
}
