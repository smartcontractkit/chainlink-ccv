package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

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
}
