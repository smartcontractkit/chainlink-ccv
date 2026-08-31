package verifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

type callbackSourceReader struct {
	chainaccess.SourceReader
	callback func(context.Context)
}

func (r *callbackSourceReader) SetCriticalSourceInvariantCallback(callback func(context.Context)) {
	r.callback = callback
}

func TestInstrumentSourceReader(t *testing.T) {
	const selector = protocol.ChainSelector(5009297550715157269)
	ctx := context.Background()
	latest := &protocol.BlockHeader{Number: 101}
	finalized := &protocol.BlockHeader{Number: 99}
	delegate := mocks.NewMockSourceReader(t)
	delegate.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Once()
	configurableReader := &callbackSourceReader{SourceReader: delegate}
	verifierMonitoring := monitoring.NewFakeVerifierMonitoring()

	reader, err := instrumentSourceReader(configurableReader, "verifier-1", selector, verifierMonitoring)
	require.NoError(t, err)
	require.NotNil(t, configurableReader.callback)

	gotLatest, gotFinalized, err := reader.LatestAndFinalizedBlock(ctx)
	require.NoError(t, err)
	require.Equal(t, latest, gotLatest)
	require.Equal(t, finalized, gotFinalized)
	require.Equal(t, int64(101), verifierMonitoring.Fake.SourceChainLatestBLock.Load())
	require.Equal(t, int64(99), verifierMonitoring.Fake.SourceChainFinalizedBlock.Load())

	configurableReader.callback(ctx)
	require.Equal(t, int64(1), verifierMonitoring.Fake.CriticalSourceInvariantViolations.Load())
}

// TestFactoryValidate exercises the ServiceFactoryValidator implementation: the same
// decode+Validate checks Start performs, but with no secrets loading, DB connection,
// or services constructed.
func TestFactoryValidate(t *testing.T) {
	f, ok := NewCommitteeVerifierServiceFactory().(bootstrap.ServiceFactoryValidator)
	require.True(t, ok, "committee verifier factory must implement ServiceFactoryValidator")

	t.Run("valid config", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"

[committee_verifier_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000002"

[rmn_remote_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000003"
`
		require.NoError(t, f.Validate(bootstrap.JobSpec{AppConfig: appConfig}))
	})

	t.Run("invalid TOML", func(t *testing.T) {
		err := f.Validate(bootstrap.JobSpec{AppConfig: "not valid toml =="})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get app config")
	})

	t.Run("mismatched address maps", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mismatched lengths")
	})

	t.Run("both aggregator fields set", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[[aggregators]]
address = "localhost:50052"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aggregator_address is deprecated")
	})

	t.Run("message disablement rules disabled is accepted", func(t *testing.T) {
		const appConfig = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"
message_disablement_rules_disabled = true

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"

[committee_verifier_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000002"

[rmn_remote_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000003"
`
		require.NoError(t, f.Validate(bootstrap.JobSpec{AppConfig: appConfig}))
	})
}
