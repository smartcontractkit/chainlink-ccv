package verifier

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// A failing chain-status read at coordinator start must degrade to unknown
// statuses, not abort startup: the readers stay configured and become ready via
// their own retrying background init.
func TestCoordinator_Start_ToleratesChainStatusReadFailure(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain := protocol.ChainSelector(2337)
	setup := setupCurseTest(t, sourceChain, destChain, 10*time.Millisecond)
	defer setup.cleanup()

	// First read (the coordinator's startup read) fails; later reads (the source
	// reader's background init) succeed. No events are sent, so the reader's
	// fetch expectation is relaxed to an empty Maybe.
	setup.chainStatusManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Unset()
	setup.chainStatusManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(nil, errors.New("db down")).
		Once()
	setup.chainStatusManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(make(map[protocol.ChainSelector]*protocol.ChainStatusInfo), nil).
		Maybe()
	setup.mockSourceReader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Unset()
	setup.mockSourceReader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil).
		Maybe()

	require.NoError(t, setup.coordinator.Start(setup.ctx), "coordinator must start despite the status read failure")

	// The reader is configured and its background init recovers once the DB answers.
	require.NotEmpty(t, setup.coordinator.sourceReaderServices, "source readers must remain configured")
	require.Eventually(t, func() bool {
		for _, srs := range setup.coordinator.sourceReaderServices {
			if srs.Ready() != nil {
				return false
			}
		}
		return true
	}, 10*time.Second, 5*time.Millisecond, "source reader should become ready via its own retries")

	// No chains were skipped, so the coordinator itself is Ready.
	require.NoError(t, setup.coordinator.Ready())
}
