package protocol

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"

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
	rPadded, err := leftPad32(r.Bytes())
	if err != nil {
		return r32, s32, fmt.Errorf("failed to pad r: %w", err)
	}
	sPadded, err := leftPad32(s.Bytes())
	if err != nil {
		return r32, s32, fmt.Errorf("failed to pad s: %w", err)
	}
	copy(r32[:], rPadded)
	copy(s32[:], sPadded)
	return r32, s32, nil
}

func normalizeAndVerify(sig, hash []byte) (r32, s32 [32]byte, addr common.Address, err error) {
	r32, s32, err = NormalizeToV27(sig)
	if err != nil {
		return r32, s32, common.Address{}, err
	}

	// Verify our normalization actually recovers the expected address on-chain semantics.
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

// SignV27WithKeystoreSigner signs hash with the provided keystore signer and returns (r,s) such that on-chain ecrecover(hash,27,r,s) recovers the signer.
// This is equivalent to signing normally, then applying NormalizeToV27.
func SignV27WithKeystoreSigner(hash []byte, keystoreSigner interface {
	Sign(data []byte) ([]byte, error)
},
) (r32, s32 [32]byte, addr common.Address, err error) {
	sig, err := keystoreSigner.Sign(hash)
	if err != nil {
		return r32, s32, common.Address{}, err
	}

	return normalizeAndVerify(sig, hash)
}

// SignV27 signs hash with priv and returns (r,s) such that on-chain ecrecover(hash,27,r,s) recovers the signer.
// This is equivalent to signing normally, then applying NormalizeToV27.
func SignV27(hash []byte, priv *ecdsa.PrivateKey) (r32, s32 [32]byte, addr common.Address, err error) {
	// go-ethereum's crypto.Sign returns 65 bytes: R||S||V, where V is 0/1 (recovery id).
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return r32, s32, common.Address{}, err
	}

	return normalizeAndVerify(sig, hash)
}

// leftPad32 left-pads a big-endian slice to exactly 32 bytes.
// Returns an error if the input exceeds 32 bytes.
func leftPad32(b []byte) ([]byte, error) {
	if len(b) > 32 {
		return nil, fmt.Errorf("slice too long for 32-byte padding: got %d bytes", len(b))
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out, nil
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

// EncodeSignatures encodes signatures in the simple format expected by CCIP v1.7 onchain validation.
// The format is: [2 bytes signature length][concatenated R,S pairs].
func EncodeSignatures(signatures []Data) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures provided")
	}

	// Sort signatures by signer address for onchain compatibility
	sortedSignatures := make([]Data, len(signatures))
	copy(sortedSignatures, signatures)
	SortSignaturesBySigner(sortedSignatures)

	// Calculate signature length (each signature is 64 bytes: 32 R + 32 S)
	signatureLength := len(sortedSignatures) * 64
	if signatureLength > math.MaxUint16 {
		return nil, fmt.Errorf("too many signatures: %d exceeds max uint16", len(sortedSignatures))
	}

	// Create result buffer
	result := make([]byte, 2+signatureLength)

	// Write signature length as first 2 bytes (big-endian uint16)
	result[0] = byte(signatureLength >> 8)
	result[1] = byte(signatureLength)

	// Write concatenated R,S pairs
	offset := 2
	for _, sig := range sortedSignatures {
		copy(result[offset:offset+32], sig.R[:])
		offset += 32
		copy(result[offset:offset+32], sig.S[:])
		offset += 32
	}

	return result, nil
}

// DecodeSignatures decodes simple-format signature data.
// The format is: [2 bytes signature length][concatenated R,S pairs]
// Returns rs, ss arrays in the same order as they appear in the data.
func DecodeSignatures(data []byte) ([][32]byte, [][32]byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("signature data too short: need at least 2 bytes for length")
	}

	// Read signature length from first 2 bytes (big-endian uint16)
	signatureLength := uint16(data[0])<<8 | uint16(data[1])

	// Validate data length
	expectedLength := 2 + int(signatureLength)
	if len(data) < expectedLength {
		return nil, nil, fmt.Errorf("signature data too short: expected %d bytes, got %d", expectedLength, len(data))
	}

	// Validate signature length is multiple of 64 (32 R + 32 S per signature)
	if signatureLength%64 != 0 {
		return nil, nil, fmt.Errorf("invalid signature length: %d is not a multiple of 64", signatureLength)
	}

	numSignatures := int(signatureLength) / 64
	if numSignatures == 0 {
		return nil, nil, fmt.Errorf("no signatures found")
	}

	// Extract R and S arrays
	rs := make([][32]byte, numSignatures)
	ss := make([][32]byte, numSignatures)

	offset := 2
	for i := range numSignatures {
		copy(rs[i][:], data[offset:offset+32])
		offset += 32
		copy(ss[i][:], data[offset:offset+32])
		offset += 32
	}

	return rs, ss, nil
}

// RecoverECDSASigners recovers signer addresses from signatures and a hash.
// This is useful after decoding signatures when you need the signer addresses.
func RecoverECDSASigners(hash [32]byte, rs, ss [][32]byte) ([]common.Address, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays have different lengths: %d vs %d", len(rs), len(ss))
	}

	signers := make([]common.Address, len(rs))
	for i := range rs {
		signer, err := RecoverECDSASigner(hash, rs[i], ss[i])
		if err != nil {
			return nil, fmt.Errorf("failed to recover signer for signature %d: %w", i, err)
		}
		signers[i] = signer
	}

	return signers, nil
}

func RecoverECDSASigner(hash, r, s [32]byte) (common.Address, error) {
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

func verifySig(rb, sb [32]byte, signer common.Address) error {
	r := new(big.Int).SetBytes(rb[:])
	s := new(big.Int).SetBytes(sb[:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
		return fmt.Errorf("values R and S must be valid curve scalars (0 < value < n)")
	}
	if signer == (common.Address{}) {
		return fmt.Errorf("signer address cannot be zero")
	}
	return nil
}

// SingleECDSASignatureSize is the exact size of an encoded EVM signature: R(32) + S(32) + Address(20) = 84 bytes.
const SingleECDSASignatureSize = 84

// EncodeSingleECDSASignature encodes a single EVM signature as R||S||Signer (84 bytes).
// This format is used by verifiers when sending individual signatures to the aggregator.
// Format: [32 bytes R][32 bytes S][20 bytes EVM Signer Address].
func EncodeSingleECDSASignature(sig Data) ([]byte, error) {
	if err := verifySig(sig.R, sig.S, sig.Signer); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	result := make([]byte, SingleECDSASignatureSize)
	copy(result[0:32], sig.R[:])
	copy(result[32:64], sig.S[:])
	copy(result[64:84], sig.Signer[:])

	return result, nil
}

// DecodeSingleECDSASignature decodes a single EVM signature from R||S||Signer format (84 bytes).
// Returns the R, S components and the EVM signer address.
func DecodeSingleECDSASignature(data []byte) (r, s [32]byte, signer common.Address, err error) {
	if len(data) != SingleECDSASignatureSize {
		return r, s, signer, fmt.Errorf("signature data must be exactly %d bytes, got %d", SingleECDSASignatureSize, len(data))
	}

	copy(r[:], data[0:32])
	copy(s[:], data[32:64])
	copy(signer[:], data[64:84])

	if err := verifySig(r, s, signer); err != nil {
		return [32]byte{}, [32]byte{}, common.Address{}, fmt.Errorf("invalid signature: %w", err)
	}

	return r, s, signer, nil
}
