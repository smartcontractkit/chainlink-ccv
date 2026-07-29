package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// JD stores OnchainSigningAddress as bare hex. A CL node decodes the signer_address in a
// ccvcommitteeverifier job spec with hexutil.Decode, which rejects a string without the 0x prefix
// and fails job creation, so the address has to be canonical by the time it reaches a job spec.
func TestEVMSigningIdentityReaderCanonicalisesAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want string
	}{
		{"bare hex from JD", "47a5eed5c86da7dd9bb75488cd3832dd6782252e", "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e"},
		{"already prefixed", "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e", "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e"},
		{"mixed case", "0x47A5EED5C86DA7DD9BB75488CD3832DD6782252E", "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := EVMSigningIdentityReader{}.FromBundle(
				&nodev1.OCR2Config_OCRKeyBundle{OnchainSigningAddress: tt.addr})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEVMSigningIdentityReaderErrors(t *testing.T) {
	t.Parallel()

	_, err := EVMSigningIdentityReader{}.FromBundle(nil)
	require.ErrorContains(t, err, "nil OCR key bundle")

	_, err = EVMSigningIdentityReader{}.FromBundle(&nodev1.OCR2Config_OCRKeyBundle{})
	require.ErrorContains(t, err, "OnchainSigningAddress is empty")
}

// Registering a reader says which field of the bundle carries the family's identity. It must not
// also decide whether the result is canonical, or the address a caller gets back changes shape
// depending on whether some other package's init() has run.
func TestSigningIdentityFromBundleNormalizesWithAndWithoutReader(t *testing.T) {
	const family = "test-family-normalized"
	const raw = "47a5eed5c86da7dd9bb75488cd3832dd6782252e"

	RegisterAddressNormalizer(family, CanonicalEVMAddress)

	bundle := &nodev1.OCR2Config_OCRKeyBundle{OnchainSigningAddress: raw}

	// No reader registered: the fallback path reads OnchainSigningAddress.
	got, err := SigningIdentityFromBundle(family, bundle)
	require.NoError(t, err)
	assert.Equal(t, "0x"+raw, got)

	// With a reader registered, the same family must still yield the canonical form.
	RegisterSigningIdentityReader(family, EVMSigningIdentityReader{})
	got, err = SigningIdentityFromBundle(family, bundle)
	require.NoError(t, err)
	assert.Equal(t, "0x"+raw, got, "registering a reader must not change the form of the address")
}
