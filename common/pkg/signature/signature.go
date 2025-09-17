package signature

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// curve order n for secp256k1.
var secpN = crypto.S256().Params().N

// Data represents a signature with its associated signer address.
type Data struct {
	R      [32]byte
	S      [32]byte
	Signer common.Address
}

// Keccak256 computes the Keccak256 hash of the input.
func Keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

// NormalizeToV27 takes a standard 65-byte Ethereum signature (R||S||V) and
// rewrites it so that it is valid for ecrecover(hash, 27, r, s) on-chain.
// If V == 28 (or == 1 if your signer returns 0/1), we flip s := n - s and set V := 27.
// Output r,s are 32-byte big-endian scalars suitable for Solidity bytes32.
func NormalizeToV27(sig65 []byte) (r32, s32 [32]byte, err error) {
	if len(sig65) != 65 {
		return r32, s32, errors.New("signature must be 65 bytes")
	}
	r := new(big.Int).SetBytes(sig65[0:32])
	s := new(big.Int).SetBytes(sig65[32:64])
	v := uint64(sig65[64])

	// Accept both conventions: 27/28 or 0/1
	switch v {
	case 0, 1:
		v += 27
	case 27, 28:
		// ok
	default:
		return r32, s32, errors.New("invalid v (expected 0/1/27/28)")
	}

	// Basic scalar checks (defense in depth)
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
		return r32, s32, errors.New("invalid r or s")
	}

	// If v == 28, flip s and set v = 27 so on-chain ecrecover(hash, 27, r, s) will work.
	if v == 28 {
		s.Sub(secpN, s)
		if s.Sign() == 0 {
			return r32, s32, errors.New("s became zero after flip")
		}
	}

	// Serialize back to fixed 32-byte big-endian
	copy(r32[:], leftPad32(r.Bytes()))
	copy(s32[:], leftPad32(s.Bytes()))
	return r32, s32, nil
}

// SignV27 signs hash with priv and returns (r,s) such that on-chain ecrecover(hash,27,r,s) recovers the signer.
// This is equivalent to signing normally, then applying NormalizeToV27.
func SignV27(hash []byte, priv *ecdsa.PrivateKey) (r32, s32 [32]byte, addr common.Address, err error) {
	// go-ethereum's crypto.Sign returns 65 bytes: R||S||V, where V is 0/1 (recovery id).
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return r32, s32, common.Address{}, err
	}
	r32, s32, err = NormalizeToV27(sig)
	if err != nil {
		return r32, s32, common.Address{}, err
	}

	// Optional: verify our normalization actually recovers the expected address on-chain semantics.
	// We emulate ecrecover(hash,27,r,s) by reconstructing a 65B sig with v=0 and running SigToPub.
	check := make([]byte, 65)
	copy(check[0:32], r32[:])
	copy(check[32:64], s32[:])
	check[64] = 0 // SigToPub expects 0/1, not 27/28

	pub, err := crypto.SigToPub(hash, check)
	if err != nil {
		return r32, s32, common.Address{}, err
	}
	return r32, s32, crypto.PubkeyToAddress(*pub), nil
}

// Helper: left-pad a big-endian slice to 32 bytes.
func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// SortSignaturesBySigner sorts signatures by signer address in ascending order.
// This is required for onchain validation which expects ordered signatures.
func SortSignaturesBySigner(signatures []Data) {
	sort.Slice(signatures, func(i, j int) bool {
		// Compare addresses as big integers (uint160)
		addrI := signatures[i].Signer.Big()
		addrJ := signatures[j].Signer.Big()
		return addrI.Cmp(addrJ) < 0
	})
}

// EncodeSignaturesABI encodes signatures using ABI encoding compatible with onchain validation.
// The format matches the expected ccvData structure: abi.encode(ccvArgs, rs, ss).
func EncodeSignaturesABI(ccvArgs []byte, signatures []Data) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures to encode")
	}

	// Extract rs and ss arrays
	rs := make([][32]byte, len(signatures))
	ss := make([][32]byte, len(signatures))
	for i, sig := range signatures {
		rs[i] = sig.R
		ss[i] = sig.S
	}

	// Define ABI types for encoding
	bytes32ArrayType, err := abi.NewType("bytes32[]", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes32[] type: %w", err)
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes type: %w", err)
	}

	// Create arguments for ABI encoding
	arguments := abi.Arguments{
		{Type: bytesType},
		{Type: bytes32ArrayType},
		{Type: bytes32ArrayType},
	}

	// Encode using ABI
	encoded, err := arguments.Pack(ccvArgs, rs, ss)
	if err != nil {
		return nil, fmt.Errorf("failed to ABI encode signatures: %w", err)
	}

	return encoded, nil
}

// DecodeSignaturesABI decodes ABI-encoded signature data.
// Returns ccvArgs, rs, ss arrays, and signer addresses (in the same order as signatures).
func DecodeSignaturesABI(data []byte) ([]byte, [][32]byte, [][32]byte, error) {
	if len(data) == 0 {
		return nil, nil, nil, fmt.Errorf("empty signature data")
	}

	// Define ABI types for decoding
	bytes32ArrayType, err := abi.NewType("bytes32[]", "", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create bytes32[] type: %w", err)
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create bytes type: %w", err)
	}

	// Create arguments for ABI decoding
	arguments := abi.Arguments{
		{Type: bytesType},
		{Type: bytes32ArrayType},
		{Type: bytes32ArrayType},
	}

	// Decode using ABI
	decoded, err := arguments.Unpack(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to ABI decode signatures: %w", err)
	}

	if len(decoded) != 3 {
		return nil, nil, nil, fmt.Errorf("expected 3 decoded values, got %d", len(decoded))
	}

	ccvArgs, ok := decoded[0].([]byte)
	if !ok {
		return nil, nil, nil, fmt.Errorf("failed to decode ccvArgs as bytes")
	}

	rs, ok := decoded[1].([][32]byte)
	if !ok {
		return nil, nil, nil, fmt.Errorf("failed to decode rs as [][32]byte")
	}

	ss, ok := decoded[2].([][32]byte)
	if !ok {
		return nil, nil, nil, fmt.Errorf("failed to decode ss as [][32]byte")
	}

	if len(rs) != len(ss) {
		return nil, nil, nil, fmt.Errorf("rs and ss arrays have different lengths: %d vs %d", len(rs), len(ss))
	}

	// For decoding, we can't recover signer addresses without the original hash
	// The caller will need to provide the hash if they need signer addresses
	return ccvArgs, rs, ss, nil
}

// RecoverSigners recovers signer addresses from signatures and a hash.
// This is useful after decoding signatures when you need the signer addresses.
func RecoverSigners(hash [32]byte, rs, ss [][32]byte) ([]common.Address, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays have different lengths: %d vs %d", len(rs), len(ss))
	}

	signers := make([]common.Address, len(rs))
	for i := 0; i < len(rs); i++ {
		signer, err := RecoverSigner(hash, rs[i], ss[i])
		if err != nil {
			return nil, fmt.Errorf("failed to recover signer for signature %d: %w", i, err)
		}
		signers[i] = signer
	}

	return signers, nil
}

func RecoverSigner(hash, r, s [32]byte) (common.Address, error) {
	// Create signature with v=0 (crypto.Ecrecover expects 0/1, not 27/28)
	sig := make([]byte, 65)
	copy(sig[0:32], r[:])
	copy(sig[32:64], s[:])
	sig[64] = 0 // Always use v=0 since we normalize all signatures to v=27

	// Recover public key
	pubKey, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key for signature: %w", err)
	}

	// Convert to address
	unmarshalledPub, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to unmarshal public key for signature: %w", err)
	}

	signer := crypto.PubkeyToAddress(*unmarshalledPub)

	return signer, nil
}
