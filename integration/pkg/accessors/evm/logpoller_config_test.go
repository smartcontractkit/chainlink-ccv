package evm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

// fakeORM embeds the interface and implements nothing: the builder must not call the ORM.
type fakeORM struct{ logpoller.ORM }

type fakeEnabledLogPoller struct{ logpoller.LogPoller }

// One test for both deployment paths, which build their reader config through NewLogPollerConfig.
func TestNewLogPollerConfig(t *testing.T) {
	t.Parallel()

	for _, verifierID := range []string{"verifier-1", "committee-a", "x"} {
		t.Run(verifierID, func(t *testing.T) {
			t.Parallel()
			lp := fakeEnabledLogPoller{}
			orm := fakeORM{}
			cfg := NewLogPollerConfig(lp, orm, verifierID)

			require.Equal(t, lp, cfg.LogPoller)
			require.Equal(t, orm, cfg.ORM)
			require.Equal(t, verifierID, cfg.VerifierID)
			require.Equal(t, DefaultMessageSentLogRetention, cfg.Retention)

			params := testSourceReaderParams(t, heads.NullTracker)
			reader, err := NewLogPollerSourceReader(t.Context(), params, cfg)
			require.NoError(t, err)
			require.Equal(t,
				logpoller.FilterName("ccv-verifier", verifierID, params.OnRampAddress.Hex()),
				reader.(*LogPollerSourceReader).filterName)
		})
	}
}
