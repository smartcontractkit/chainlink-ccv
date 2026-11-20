package sourcereader

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/committee"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestMigrationHandoffSignsMessageBelowDefaultLookback(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	signer, _, signerAddress, err := commit.NewECDSAMessageSigner(crypto.FromECDSA(privateKey))
	require.NoError(t, err)

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	events[0].Receipts[0].Issuer = signerAddress
	executorAddress := events[0].Receipts[1].Issuer
	require.Less(t, events[0].BlockNumber, uint64(1500), "the event must lie below finalized_head - 500")

	reader := mocks.NewMockSourceReader(t)
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(
		&protocol.BlockHeader{Number: 2100}, &protocol.BlockHeader{Number: 2000}, nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(100), uint64(0)).Return(events, nil).Once()
	status := mocks.NewMockChainStatusManager(t)
	status.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{chain}).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Once()
	curse := mocks.NewMockCurseCheckerService(t)
	curse.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	srs, _, queue := newTestSRS(t, chain, reader, status, curse, time.Millisecond, 5000)
	initial := uint64(100)
	srs.sourceCfg.InitialStartBlock = &initial

	start, err := srs.initializeStartBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, initial, start)
	srs.lastProcessedFinalizedBlock.Store(start)
	srs.startBlockInitialized.Store(true)
	runPollCycle(t.Context(), srs, 2100, 2000)
	published := queue.Published()
	require.Len(t, published, 1)
	require.Equal(t, events[0].BlockNumber, published[0].BlockNumber)

	cv, err := commit.NewCommitVerifier(verifier.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			chain: {
				ChainSelector:          chain,
				VerifierAddress:        signerAddress,
				DefaultExecutorAddress: executorAddress,
			},
		},
	}, signerAddress, signer, logger.Test(t), verifiermonitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)
	results := cv.VerifyMessages(t.Context(), published)
	require.Len(t, results, 1)
	require.Nil(t, results[0].Error)
	require.NotNil(t, results[0].Result)

	messageID, err := protocol.NewBytes32FromString(published[0].MessageID)
	require.NoError(t, err)
	hash, err := committee.NewSignableHash(messageID, published[0].ReceiptBlobs[0].Blob)
	require.NoError(t, err)
	r, s, err := protocol.DecodeSingleECDSASignature(results[0].Result.Signature)
	require.NoError(t, err)
	recovered, err := protocol.RecoverECDSASigner(hash, r, s)
	require.NoError(t, err)
	require.Equal(t, signerAddress.Bytes(), recovered.Bytes(), "the migrating NOP's own key signed the gap message")
}
