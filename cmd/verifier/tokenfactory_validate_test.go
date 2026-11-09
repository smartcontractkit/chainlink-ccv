package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/cctpdomains" // registers the EVM base CCTP domain table
)

func TestTokenFactoryValidate(t *testing.T) {
	f, ok := NewTokenVerifierServiceFactory().(bootstrap.ServiceFactoryValidator)
	require.True(t, ok, "token verifier factory must implement ServiceFactoryValidator")

	const validConfig = `
[[token_verifiers]]
verifier_id = "cctp-CCTPVerifier"
type = "cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
attestation_api_timeout = "3s"
`

	t.Run("valid config", func(t *testing.T) {
		require.NoError(t, f.Validate(bootstrap.JobSpec{AppConfig: validConfig}))
	})

	t.Run("invalid TOML", func(t *testing.T) {
		err := f.Validate(bootstrap.JobSpec{AppConfig: "not valid toml =="})
		require.ErrorContains(t, err, "unable to decode app config")
	})

	t.Run("duplicate verifier_id", func(t *testing.T) {
		const appConfig = validConfig + `
[[token_verifiers]]
verifier_id = "cctp-CCTPVerifier"
type = "cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.ErrorContains(t, err, `duplicate verifier_id "cctp-CCTPVerifier"`)
	})

	// Regression: prod configs carried a bare-nanosecond duration, which used to
	// fall back to the default instead of failing.
	t.Run("bare integer duration", func(t *testing.T) {
		const appConfig = `
[[token_verifiers]]
verifier_id = "cctp-CCTPVerifier"
type = "cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
attestation_api_timeout = 3000000000
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.ErrorContains(t, err, "must be a quoted string")
	})

	// Regression: a custom UnmarshalTOML consumes the whole entry, so the TOML
	// decoder reports no undecoded keys and a drifted key used to be dropped.
	t.Run("unknown key in a verifier entry", func(t *testing.T) {
		const appConfig = `
[[token_verifiers]]
verifier_id = "lombard_2.0.0"
type = "lombard"
version = "1.0"
attestation_api = "https://lombard-api.example.com"
verifier_addresses = { "1" = "0x0000000000000000000000000000000000000001" }
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.ErrorContains(t, err, "unknown keys for lombard verifier")
		require.ErrorContains(t, err, "verifier_addresses")
	})

	t.Run("unknown top-level key", func(t *testing.T) {
		// A key after the [[token_verifiers]] header would belong to that entry,
		// so the top-level key must come first.
		const appConfig = "bogus_top_level = 1\n" + validConfig
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.ErrorContains(t, err, "undecoded keys")
		assert.Contains(t, err.Error(), "bogus_top_level")
	})

	t.Run("unsupported verifier type", func(t *testing.T) {
		const appConfig = `
[[token_verifiers]]
verifier_id = "zk-x"
type = "zk"
version = "1.0"
`
		err := f.Validate(bootstrap.JobSpec{AppConfig: appConfig})
		require.ErrorContains(t, err, "unsupported verifier type zk and version 1.0")
	})
}

func TestTokenFactoryValidate_CCTPDomains(t *testing.T) {
	f := NewTokenVerifierServiceFactory().(bootstrap.ServiceFactoryValidator)

	const inTable = "16015286601757825753"   // Sepolia, in the EVM base table
	const notInTable = "1910019406958449359" // Etherlink testnet, EVM but not in the table
	const invalidSelector = "111111111"      // invalid chain selector, validations should always fail

	spec := func(chain, overrides string) bootstrap.JobSpec {
		return bootstrap.JobSpec{AppConfig: `
[[token_verifiers]]
verifier_id = "cctp"
type = "cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
verifier_addresses = { ` + chain + ` = "0x0000000000000000000000000000000000000001" }
` + overrides}
	}

	t.Run("EVM chain in table", func(t *testing.T) {
		require.NoError(t, f.Validate(spec(`"`+inTable+`"`, "")))
	})

	t.Run("EVM chain in neither table nor overrides fails", func(t *testing.T) {
		err := f.Validate(spec(`"`+notInTable+`"`, ""))
		require.ErrorContains(t, err, "no CCTP domain for chain selectors ["+notInTable+"]")
	})

	t.Run("override covers it", func(t *testing.T) {
		overrides := "[token_verifiers.cctp_domain_mapping]\n\"" + notInTable + "\" = 40\n"
		require.NoError(t, f.Validate(spec(`"`+notInTable+`"`, overrides)))
	})

	t.Run("invalid chain selector in config", func(t *testing.T) {
		err := f.Validate(spec(`"`+invalidSelector+`"`, ""))
		require.ErrorContains(t, err, "unknown chain selector")
	})
}
