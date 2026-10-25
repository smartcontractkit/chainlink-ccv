package constructors

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// logPollerChain is a node chain with the log poller enabled, so the in-node verifier reads logs from it.
type logPollerChain struct {
	stubChain
	lp logpoller.LogPoller
}

func (c logPollerChain) LogPoller() logpoller.LogPoller { return c.lp }

func TestNewChainSourceReader(t *testing.T) {
	chain := logPollerChain{stubChain: stubChain{chainClient: clienttest.NewClient(t)}, lp: lpmocks.NewLogPoller(t)}
	params := evm.SourceReaderParams{
		ChainClient:          chain.Client(),
		HeadTracker:          chain.HeadTracker(),
		OnRampAddress:        common.HexToAddress("0x1234"),
		CCIPMessageSentTopic: common.HexToHash("0x01").Hex(),
		ChainSelector:        protocol.ChainSelector(5009297550715157269),
		Logger:               logger.Test(t),
		HeaderFetchBatchSize: 25,
	}

	reader, reporter, err := newChainSourceReader(chain, params, "test-verifier")
	require.NoError(t, err)
	require.IsType(t, &evm.LogPollerSourceReader{}, reader)
	require.NotNil(t, reporter)
}
