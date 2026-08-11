package constructors

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestFinalityCheckerDisabled(t *testing.T) {
	const selector = protocol.ChainSelector(5009297550715157269)

	require.True(t, finalityCheckerDisabled([]string{"1", "5009297550715157269"}, selector))
	require.False(t, finalityCheckerDisabled([]string{"1", "2"}, selector))
}
