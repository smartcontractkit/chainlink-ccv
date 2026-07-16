package changesets

import (
	"encoding/hex"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
)

// TestNOPIdentities_ResolvesCantonSignerAsEVM verifies that a Canton NOP known to JD
// under both the "canton" family (raw secp256k1 public key) and the "evm" family
// (EVM-derived address) resolves correctly in both directions. JD pushes both
// variants at registration, and fetch_signing_keys registers both — no keccak
// derivation is needed in the changeset layer.
func TestNOPIdentities_ResolvesCantonSignerAsEVM(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)

	rawPubKey := hex.EncodeToString(gethcrypto.FromECDSAPub(&priv.PublicKey))
	evmAddr := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()

	const cantonNOP = "canton-default-verifier-1"

	// JD returns both variants: the raw public key under canton, and the EVM
	// address under evm (read from OnchainSigningAddress by the EVM reader).
	signingKeys := fetch_signing_keys.SigningKeysByNOP{
		cantonNOP: {
			chainsel.FamilyCanton: rawPubKey,
			chainsel.FamilyEVM:    evmAddr,
		},
	}

	ids := newNOPIdentities(signingKeys)

	// The EVM address resolves back to the Canton NOP.
	alias, ok := ids.AliasForSigner(chainsel.FamilyEVM, evmAddr)
	require.True(t, ok, "canton NOP's EVM signer should resolve back to the NOP")
	require.Equal(t, cantonNOP, string(alias))

	// The directly-declared canton identity also resolves.
	alias, ok = ids.AliasForSigner(chainsel.FamilyCanton, rawPubKey)
	require.True(t, ok)
	require.Equal(t, cantonNOP, string(alias))
}

// TestNOPIdentities_DirectSignerWinsOverDuplicate ensures a family's directly-declared
// signer address is never shadowed by another NOP registering the same address (which
// would happen if two NOPs share the same key). First writer wins.
func TestNOPIdentities_DirectSignerWinsOverDuplicate(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	rawPubKey := hex.EncodeToString(gethcrypto.FromECDSAPub(&priv.PublicKey))
	evmAddr := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()

	signingKeys := fetch_signing_keys.SigningKeysByNOP{
		"evm-nop":    {chainsel.FamilyEVM: evmAddr},
		"canton-nop": {chainsel.FamilyCanton: rawPubKey, chainsel.FamilyEVM: evmAddr},
	}

	ids := newNOPIdentities(signingKeys)

	// evmAddr is declared by both NOPs; the first-registered one (alphabetically) wins.
	alias, ok := ids.AliasForSigner(chainsel.FamilyEVM, evmAddr)
	require.True(t, ok)
	require.Equal(t, "canton-nop", string(alias))
}
