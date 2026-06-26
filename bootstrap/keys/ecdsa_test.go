package keys

import (
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEVMAddressFromPublicKey(t *testing.T) {
	t.Parallel()

	privKey, err := gethcrypto.GenerateKey()
	require.NoError(t, err)

	pubKeyBytes := gethcrypto.FromECDSAPub(&privKey.PublicKey) // uncompressed, 65 bytes
	wantAddr := gethcrypto.PubkeyToAddress(privKey.PublicKey).Hex()

	addr, pubKeyHex, err := EVMAddressFromPublicKey(pubKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, wantAddr, addr)
	assert.Equal(t, len(pubKeyBytes)*2, len(pubKeyHex)) // hex is 2 chars per byte

	t.Run("invalid key returns error", func(t *testing.T) {
		_, _, err := EVMAddressFromPublicKey([]byte("not a key"))
		require.Error(t, err)
	})
}
