package keys

import (
	"encoding/hex"
	"fmt"
	"strings"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// EVMAddressFromPublicKey derives the Ethereum address from an uncompressed secp256k1 public key
// (65 bytes, 0x04-prefixed) returned by the keystore for ECDSA_S256 keys.
// Returns the EIP-55 checksummed address (0x-prefixed) and the full uncompressed public key hex.
func EVMAddressFromPublicKey(pubKeyBytes []byte) (address, pubKeyHex string, err error) {
	pubKey, err := gethcrypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to unmarshal secp256k1 public key: %w", err)
	}
	return gethcrypto.PubkeyToAddress(*pubKey).Hex(), hex.EncodeToString(pubKeyBytes), nil
}

// SolanaAddressFromPublicKey derives the Solana onchain signing address from an uncompressed
// secp256k1 public key. Solana follows the same secp256k1 → keccak256 derivation as EVM but
// formats the address as lowercase hex without the 0x prefix, matching the chainlink node's
// prior art in its Solana OCR2 keyring.
func SolanaAddressFromPublicKey(pubKeyBytes []byte) (string, error) {
	addr, _, err := EVMAddressFromPublicKey(pubKeyBytes)
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimPrefix(addr, "0x")), nil
}

// RawPubKeyHex returns the uncompressed secp256k1 public key (65 bytes, 0x04-prefixed) as
// lowercase hex without any additional prefix. Used by chains (e.g. Aptos) whose onchain
// contracts verify against the full public key rather than a derived address.
func RawPubKeyHex(pubKeyBytes []byte) string {
	return hex.EncodeToString(pubKeyBytes)
}
