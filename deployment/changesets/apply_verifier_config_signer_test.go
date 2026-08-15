package changesets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// buildSpecForSigner builds a single consolidated verifier job spec for a NOP whose EVM signer
// address is signerAddress, and returns the signer_address the spec carries.
func buildSpecForSigner(t *testing.T, signerAddress string) string {
	t.Helper()
	registerEVMChainTypeForIdentities()

	specs, _, err := buildVerifierJobSpecs(
		map[string]*adapters.VerifierContractAddresses{
			"1": {
				CommitteeVerifierAddress: "0xCommittee1",
				OnRampAddress:            "0xOnRamp1",
			},
		},
		map[string]string{"1": "0xExec1"},
		nil,
		[]verifierNOPInput{{
			Alias:                 "nop1",
			SignerAddressByFamily: map[string]string{"evm": signerAddress},
		}},
		verifierCommitteeInput{
			Qualifier:  "default",
			NOPAliases: []shared.NOPAlias{"nop1"},
			Aggregators: []AggregatorRef{
				{Name: "agg-a", Address: "agg-a:50051", InsecureAggregatorConnection: true},
			},
		},
		"",
		nil,
		"evm",
		true,
	)
	require.NoError(t, err)

	jobs := specs["nop1"]
	require.Len(t, jobs, 1)
	for _, spec := range jobs {
		return parseVerifierConfig(t, spec).SignerAddress
	}
	return ""
}

// A CL node decodes signer_address with hexutil.Decode, which rejects a string without an 0x
// prefix and fails to create the ccvcommitteeverifier job. JD stores an OCR key bundle's
// OnchainSigningAddress as bare hex, so an address arriving from JD — or written bare in a
// topology — has to be canonicalised before it reaches the spec.
func TestBuildVerifierJobSpecs_CanonicalisesSignerAddress(t *testing.T) {
	const bare = "47a5eed5c86da7dd9bb75488cd3832dd6782252e"

	assert.Equal(t, "0x"+bare, buildSpecForSigner(t, bare),
		"a bare address must reach the job spec 0x-prefixed")
}

// An address already in canonical form must survive unchanged, so re-running the changeset does
// not rewrite a spec and register as drift against the deployment-generated one.
func TestBuildVerifierJobSpecs_SignerAddressIsIdempotent(t *testing.T) {
	const canonical = "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e"

	assert.Equal(t, canonical, buildSpecForSigner(t, canonical))
}
