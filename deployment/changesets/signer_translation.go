package changesets

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	gethcommon "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	chainsel "github.com/smartcontractkit/chain-selectors"
)

// This mirrors the cross-family signer translation in
// chainlink-ccip/deployment/v2_0_0/changesets/lane_signing_helpers.go (added in #2169
// "fix cross-family signer lookup"). That change fixed the *forward* path — deriving a
// NOP's signer address for a destination family when the lane changeset writes it
// on-chain. This is the *inverse* path: when reconstructing committee membership from
// on-chain state (CommitteeInputFromState -> NOPIdentities.AliasForSigner), an on-chain
// signer recorded in the verifier chain's family (e.g. a Canton verifier's EVM address on
// an EVM committee verifier) must resolve back to the NOP even though JD only knows that
// NOP under its own family (canton). Without the same translation the reconstruction
// fails with "on-chain signer ... has no JD-known NOP".

// rawPubKeySourceFamily is a synthetic "family" tag used only as a translation source,
// standing for a NOP's raw public key fetched directly from JD rather than derived from
// any one chain family's own address representation. It is never a real chain family and
// must never be passed as a translation target.
const rawPubKeySourceFamily = "xxx_notarealfamily_raw_pubkey"

// addressClassFamilies are chain families whose signer identity is a 20-byte address
// derived via secp256k1 -> keccak256 (EVM-style). Members encode identical bytes and
// differ only in string formatting, so they are freely interconvertible in both
// directions.
var addressClassFamilies = map[string]bool{
	chainsel.FamilyEVM:    true,
	chainsel.FamilySolana: true,
}

// rawPubKeyClassFamilies are chain families (plus the synthetic rawPubKeySourceFamily)
// whose signer identity is the full uncompressed secp256k1 public key, hex-encoded with
// no per-family formatting differences. Members are interchangeable as-is.
var rawPubKeyClassFamilies = map[string]bool{
	chainsel.FamilyAptos:   true,
	chainsel.FamilyStellar: true,
	chainsel.FamilyCanton:  true,
	rawPubKeySourceFamily:  true,
}

// translatableSignerFamilies is the set of real chain families the inverse index is
// populated for. When a NOP has a signer identity known for one family, its address in
// every other family in this set that can be derived is precomputed, so AliasForSigner
// resolves an on-chain signer regardless of which family it was recorded in.
var translatableSignerFamilies = []string{
	chainsel.FamilyEVM,
	chainsel.FamilySolana,
	chainsel.FamilyAptos,
	chainsel.FamilyStellar,
	chainsel.FamilyCanton,
}

// signerAddressForFamily derives the signer address a NOP would present on targetFamily
// from whatever identities it already has: its per-family signer addresses (JD- or
// state-sourced) and/or its raw public key. It returns ok=false when no candidate can be
// translated into targetFamily (e.g. only an address-class family is known but the target
// needs a raw public key, which a hashed address cannot yield).
func signerAddressForFamily(directByFamily map[string]string, rawPubKey, targetFamily string) (string, bool) {
	candidates := make(map[string]string, len(directByFamily)+1)
	for family, addr := range directByFamily {
		if addr != "" {
			candidates[family] = addr
		}
	}
	if rawPubKey != "" {
		if _, exists := candidates[rawPubKeySourceFamily]; !exists {
			candidates[rawPubKeySourceFamily] = rawPubKey
		}
	}
	delete(candidates, targetFamily)

	families := make([]string, 0, len(candidates))
	for family := range candidates {
		families = append(families, family)
	}
	sort.Strings(families) // deterministic when more than one source family is available

	for _, family := range families {
		if translated, err := translateSignerAddress(family, candidates[family], targetFamily); err == nil {
			return translated, true
		}
	}
	return "", false
}

// translateSignerAddress converts a signer identity stored under sourceFamily into the
// representation targetFamily expects, valid only when both families sign with the same
// underlying secp256k1 key.
//
// Address-class families (evm, solana) store the same 20 bytes and translate in both
// directions. Raw-pubkey-class families (aptos, stellar, canton) store the same
// hex-encoded public key and translate in both directions. Deriving an address-class
// value from a raw public key is one-directional: an address is a keccak256 hash of the
// public key, so recovering the public key from an address is not possible — that
// direction returns an error instead of a wrong answer.
func translateSignerAddress(sourceFamily, value, targetFamily string) (string, error) {
	switch {
	case addressClassFamilies[sourceFamily] && addressClassFamilies[targetFamily]:
		addrBytes, err := decodeAddressHex(value)
		if err != nil {
			return "", fmt.Errorf("decode %s signer address: %w", sourceFamily, err)
		}
		return formatAddressForFamily(addrBytes, targetFamily)
	case rawPubKeyClassFamilies[sourceFamily] && rawPubKeyClassFamilies[targetFamily]:
		return strings.ToLower(strings.TrimPrefix(value, "0x")), nil
	case rawPubKeyClassFamilies[sourceFamily] && addressClassFamilies[targetFamily]:
		pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(value), "0x"))
		if err != nil {
			return "", fmt.Errorf("decode %s raw public key: %w", sourceFamily, err)
		}
		pubKey, err := gethcrypto.UnmarshalPubkey(pubKeyBytes)
		if err != nil {
			return "", fmt.Errorf("unmarshal %s public key: %w", sourceFamily, err)
		}
		return formatAddressForFamily(gethcrypto.PubkeyToAddress(*pubKey).Bytes(), targetFamily)
	case addressClassFamilies[sourceFamily] && rawPubKeyClassFamilies[targetFamily]:
		return "", fmt.Errorf(
			"cannot derive a %s raw public key from a %s address: address derivation (keccak256) is not "+
				"reversible; register the node's raw public key for family %s directly",
			targetFamily, sourceFamily, targetFamily)
	default:
		return "", fmt.Errorf("no signer address translation defined from family %s to family %s", sourceFamily, targetFamily)
	}
}

// decodeAddressHex parses a 20-byte address from hex, tolerating an optional 0x prefix
// and either case.
func decodeAddressHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("expected 20-byte address, got %d bytes", len(b))
	}
	return b, nil
}

// formatAddressForFamily renders a 20-byte address per family convention: EIP-55
// checksummed with 0x for evm, lowercase without 0x for solana.
func formatAddressForFamily(addr []byte, family string) (string, error) {
	switch family {
	case chainsel.FamilyEVM:
		return gethcommon.BytesToAddress(addr).Hex(), nil
	case chainsel.FamilySolana:
		return strings.ToLower(hex.EncodeToString(addr)), nil
	default:
		return "", fmt.Errorf("unsupported address-class family %q", family)
	}
}
