package cciptestinterfaces

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

func TestXXXNewVerifierPrivateKey(t *testing.T) {
	for _, committeeName := range []string{"default", "secondary", "tertiary"} {
		for nodeIndex := range []int{0, 1} {
			privKeyString := XXXNewVerifierPrivateKey(committeeName, nodeIndex)
			privateKeyBytes, err := commit.ReadPrivateKeyFromString(privKeyString)
			require.NoError(t, err)
			_, addr, err := commit.NewECDSAMessageSigner(privateKeyBytes)
			require.NoError(t, err)
			t.Logf("committeeName: %s, nodeIndex: %d, key: %x, signerAddress: %s", committeeName, nodeIndex, privateKeyBytes, addr.String())
		}
	}
}
