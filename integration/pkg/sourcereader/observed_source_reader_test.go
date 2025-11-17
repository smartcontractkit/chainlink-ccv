package sourcereader

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockReader := mocks.NewMockSourceReader(t)
			monitor := monitoring.NewFakeVerifierMonitoring()

			rd := NewObservedSourceReader(
				mockReader,
				verifierID,
				chainSelector,
				monitor,
			)

			mockReader.On("LatestAndFinalizedBlock", mock.Anything).
				Return(tc.latestBlock, tc.finalizedBlock, tc.returnErr).
				Once()

			_, _, err := rd.LatestAndFinalizedBlock(t.Context())
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

	rd1 := NewObservedSourceReader(
		mockReader,
		"verifier1",
		protocol.ChainSelector(1),
		monitor,
	)

	rd2 := NewObservedSourceReader(
		mockReader,
		"verifier2",
		protocol.ChainSelector(2),
		monitor,
	)

	mockReader.On("LatestAndFinalizedBlock", mock.Anything).
		Return(block1, block2, nil).
		Twice()

	_, _, err := rd1.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"source_chain", "ChainSelector(1)", "verifier_id", "verifier1"}, monitor.Fake.Labels())

	_, _, err = rd2.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"source_chain", "ChainSelector(2)", "verifier_id", "verifier2"}, monitor.Fake.Labels())
}
