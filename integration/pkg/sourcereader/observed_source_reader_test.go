package sourcereader

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

func TestNewObservedSourceReader_RejectsNilDelegate(t *testing.T) {
	monitor := monitoring.NewFakeVerifierMonitoring()
	rd, err := NewObservedSourceReader(nil, "v1", protocol.ChainSelector(1), monitor)
	require.ErrorContains(t, err, "delegate cannot be nil")
	require.Nil(t, rd)
}

func TestNewObservedSourceReader_RejectsNilMonitoring(t *testing.T) {
	mockReader := mocks.NewMockSourceReader(t)
	rd, err := NewObservedSourceReader(mockReader, "v1", protocol.ChainSelector(1), nil)
	require.ErrorContains(t, err, "monitoring cannot be nil")
	require.Nil(t, rd)
}

func TestObservedSourceReader_Values(t *testing.T) {
	verifierID := "verifier1"
	chainSelector := protocol.ChainSelector(123)
	block1 := &protocol.BlockHeader{Number: 1}
	block2 := &protocol.BlockHeader{Number: 2}

	testCases := []struct {
		name                   string
		latestBlock            *protocol.BlockHeader
		finalizedBlock         *protocol.BlockHeader
		returnErr              error
		expectedLatestBlock    int64
		expectedFinalizedBlock int64
	}{
		{
			name:                   "nothing is tracked when nil blocks are returned",
			latestBlock:            nil,
			finalizedBlock:         nil,
			returnErr:              nil,
			expectedLatestBlock:    0,
			expectedFinalizedBlock: 0,
		},
		{
			name:                   "nothing is tracked when error is returned",
			latestBlock:            block1,
			finalizedBlock:         block2,
			returnErr:              fmt.Errorf("error"),
			expectedLatestBlock:    0,
			expectedFinalizedBlock: 0,
		},
		{
			name:                   "blocks are tracked when non-nil blocks are returned",
			latestBlock:            block1,
			finalizedBlock:         block2,
			returnErr:              nil,
			expectedLatestBlock:    1,
			expectedFinalizedBlock: 2,
		},
		{
			name:                   "only latest block is tracked when finalized is nil",
			latestBlock:            block1,
			finalizedBlock:         nil,
			returnErr:              nil,
			expectedLatestBlock:    1,
			expectedFinalizedBlock: 0,
		},
		{
			name:                   "only finalized block is tracked when latest is nil",
			latestBlock:            nil,
			finalizedBlock:         block2,
			returnErr:              nil,
			expectedLatestBlock:    0,
			expectedFinalizedBlock: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockReader := mocks.NewMockSourceReader(t)
			monitor := monitoring.NewFakeVerifierMonitoring()

			rd, err := NewObservedSourceReader(
				mockReader,
				verifierID,
				chainSelector,
				monitor,
			)
			require.NoError(t, err)

			mockReader.On("LatestAndFinalizedBlock", mock.Anything).
				Return(tc.latestBlock, tc.finalizedBlock, tc.returnErr).
				Once()

			_, _, err = rd.LatestAndFinalizedBlock(t.Context())
			if tc.returnErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.expectedLatestBlock, monitor.Fake.SourceChainLatestBLock.Load())
			require.Equal(t, tc.expectedFinalizedBlock, monitor.Fake.SourceChainFinalizedBlock.Load())
		})
	}
}

func TestObservedSourceReader_Labels(t *testing.T) {
	block1 := &protocol.BlockHeader{Number: 1}
	block2 := &protocol.BlockHeader{Number: 2}

	mockReader := mocks.NewMockSourceReader(t)
	monitor := monitoring.NewFakeVerifierMonitoring()

	rd1, err := NewObservedSourceReader(
		mockReader,
		"verifier1",
		protocol.ChainSelector(1),
		monitor,
	)
	require.NoError(t, err)

	rd2, err := NewObservedSourceReader(
		mockReader,
		"verifier2",
		protocol.ChainSelector(2),
		monitor,
	)
	require.NoError(t, err)

	mockReader.On("LatestAndFinalizedBlock", mock.Anything).
		Return(block1, block2, nil).
		Twice()

	_, _, err = rd1.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"source_chain", "1", "source_chain_name", "unknown:1", "verifier_id", "verifier1"}, monitor.Fake.Labels())

	_, _, err = rd2.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"source_chain", "2", "source_chain_name", "unknown:2", "verifier_id", "verifier2"}, monitor.Fake.Labels())
}
