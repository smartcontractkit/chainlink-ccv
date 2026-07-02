package changesets

import (
	"encoding/hex"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
)

// TestNOPIdentities_ResolvesCantonSignerAsEVM reproduces the reconstruction path that
// failed after canton moved to JD-based signer sync: a canton verifier is known to JD
// only under family "canton" (its identity is the raw secp256k1 public key), but on an
// EVM committee verifier its signer is recorded as the EVM address derived from that key.
// AliasForSigner("evm", <derived address>) must resolve back to the canton NOP.
func TestNOPIdentities_ResolvesCantonSignerAsEVM(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)

	rawPubKey := hex.EncodeToString(gethcrypto.FromECDSAPub(&priv.PublicKey))
	evmAddr := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()

	const cantonNOP = "canton-default-verifier-1"

	// JD only knows this NOP under the canton family; the canton "address" is the raw
	// public key hex, and RawPubKeyByNOP carries the same key.
	signingKeys := fetch_signing_keys.SigningKeysByNOP{
		cantonNOP: {chainsel.FamilyCanton: rawPubKey},
	}
	rawPubKeyByNOP := map[string]string{cantonNOP: rawPubKey}

	ids := newNOPIdentities(signingKeys, rawPubKeyByNOP)

	alias, ok := ids.AliasForSigner(chainsel.FamilyEVM, evmAddr)
	require.True(t, ok, "canton NOP's EVM-derived signer should resolve back to the NOP")
	require.Equal(t, cantonNOP, string(alias))

	// The directly-declared canton identity still resolves.
	alias, ok = ids.AliasForSigner(chainsel.FamilyCanton, rawPubKey)
	require.True(t, ok)
	require.Equal(t, cantonNOP, string(alias))
}

// TestNOPIdentities_DirectSignerWinsOverDerived ensures a family's directly-declared
// signer address is never shadowed by one derived for another NOP.
func TestNOPIdentities_DirectSignerWinsOverDerived(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	rawPubKey := hex.EncodeToString(gethcrypto.FromECDSAPub(&priv.PublicKey))
	evmAddr := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()

	signingKeys := fetch_signing_keys.SigningKeysByNOP{
		"evm-nop":    {chainsel.FamilyEVM: evmAddr},
		"canton-nop": {chainsel.FamilyCanton: rawPubKey},
	}
	rawPubKeyByNOP := map[string]string{"canton-nop": rawPubKey}

	ids := newNOPIdentities(signingKeys, rawPubKeyByNOP)

	// evmAddr is declared directly by evm-nop and would also be derived for canton-nop
	// (same key); the direct declaration must win.
	alias, ok := ids.AliasForSigner(chainsel.FamilyEVM, evmAddr)
	require.True(t, ok)
	require.Equal(t, "evm-nop", string(alias))
}
