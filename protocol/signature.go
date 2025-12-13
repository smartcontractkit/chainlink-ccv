package protocol

import (
	"errors"
	"fmt"
)

// SignatureScheme is a uint8 that defines the identifier byte for the signature scheme used in the canonical encoding.
// Note: This scheme is only used within the CommiteeVerifier off-chain. Other verifiers do NOT need to conform to this specification.
//
// --------------------------------------------------------------------------------------------------------------------------
// | ID        | Scheme         | Curve     | Signature Size | Public Key Size   | Total Size | Notes                       |
// |-----------|----------------|-----------|----------------|-------------------|------------|-----------------------------|
// | 0x00      | Reserved       | -         | -              | -                 | -          | Placeholder                 |
// | 0x01      | ECDSA          | secp256k1 | 64 bytes       | 0 bytes (derived) | 65 bytes   | v normalized to 27          |
// | 0x02      | EdDSA          | ed25519   | 64 bytes       | 32 bytes          | 97 bytes   | Standard Ed25519            |
// | 0x03-0x7F | Reserved       | -         | -              | -                 | -          | Reserved for future schemes |
// | 0x80-0xFF | Experimental   | -         | -              | -                 | -          | Experimental/private use    |
// --------------------------------------------------------------------------------------------------------------------------
type SignatureScheme = uint8

const (
	SchemeReserved       SignatureScheme = 0x00
	SchemeReservedString string          = "Reserved"
	SchemeECDSA          SignatureScheme = 0x01
	SchemeECDSAString    string          = "ECDSA"
	SchemeEdDSA          SignatureScheme = 0x02
	SchemeEdDSAString    string          = "EdDSA"
)

const (
	SchemeSize = 1
	// ECDSA signature sizes
	ECDSASignatureSize = 64                              // R (32) + S (32)
	ECDSATotalSize     = SchemeSize + ECDSASignatureSize // 65 bytes

	// EdDSA signature sizes
	EdDSASignatureSize = 64
	EdDSAPublicKeySize = 32
	EdDSATotalSize     = SchemeSize + EdDSASignatureSize + EdDSAPublicKeySize // 97 bytes

	Keecak256HashSize = 32
)

var (
	ErrInvalidScheme         = errors.New("invalid signature scheme")
	ErrInvalidSignatureSize  = errors.New("invalid signature size")
	ErrInvalidECDSAFormat    = errors.New("invalid ECDSA signature format")
	ErrInvalidEdDSAFormat    = errors.New("invalid EdDSA signature format")
	ErrZeroSignature         = errors.New("signature cannot be zero")
	ErrInvalidPreimageLength = errors.New("invalid preimage length")
)

type Signature struct {
	Scheme    SignatureScheme
	Signature ByteSlice
	PublicKey ByteSlice
}

func SchemeString(scheme SignatureScheme) string {
	switch scheme {
	case SchemeECDSA:
		return SchemeECDSAString
	case SchemeEdDSA:
		return SchemeEdDSAString
	default:
		return SchemeReservedString
	}
}

// ECDSASignature represents an ECDSA signature in canonical format.
// Note: v is normalized to 27 so is not included in the format.
// ┌──────────┬──────────────────┬──────────────────┐
// │ Scheme   │   R (32 bytes)   │   S (32 bytes)   │
// │ (0x01)   │   big-endian     │   big-endian     │
// └──────────┴──────────────────┴──────────────────┘
// Total: 65 Bytes
type ECDSASignature struct {
	R         [32]byte
	S         [32]byte
	PublicKey [20]byte // Derived from signature + preimage. Not included in the encoding
}

func (e *ECDSASignature) Bytes() []byte {
	output := make([]byte, 65)
	return output
}

// EdDSASignature represents an EdDSA signature in canonical format.
// ┌──────────┬─────────────────────────┬───────────────┐
// │ Scheme   │   Signature (64 bytes)  │   Public Key  │
// │ (0x02)   │   little-endian         │   (32 bytes)  │
// └──────────┴─────────────────────────┴───────────────┘
// Total: 97 bytes
type EdDSASignature struct {
	Signature [64]byte
	PublicKey [32]byte
}

func (e *EdDSASignature) Bytes() []byte {
	output := make([]byte, 97)
	copy(output[0:1], []byte{SchemeEdDSA})
	copy(output[1:65], e.Signature[:])
	copy(output[65:97], e.PublicKey[:])
	return output
}

// ToECDSA converts a generic signature structure into an ECDSA signature with the public key additionally included.
func (s *Signature) ToECDSA() (ECDSASignature, error) {
	if s.Scheme != SchemeECDSA {
		return ECDSASignature{}, ErrInvalidScheme
	}

	return ECDSASignature{
		R:         [32]byte(s.Signature[0:32]),
		S:         [32]byte(s.Signature[0:64]),
		PublicKey: [20]byte(s.PublicKey),
	}, nil
}

// ToEdDSA converts a generic signature structure into an EdDSA signature with the public key additionally included.
func (s *Signature) ToEdDSA() (EdDSASignature, error) {
	if s.Scheme != SchemeEdDSA {
		return EdDSASignature{}, ErrInvalidScheme
	}

	return EdDSASignature{
		Signature: [64]byte(s.Signature),
		PublicKey: [32]byte(s.PublicKey),
	}, nil
}

func (s *Signature) Bytes() ([]byte, error) {
	switch s.Scheme {
	case SchemeECDSA:
		ecdsa, err := s.ToECDSA()
		if err != nil {
			return nil, err
		}
		return ecdsa.Bytes(), nil
	default:
		return nil, ErrInvalidScheme
	}
}

func NewSignature(scheme SignatureScheme, signature ByteSlice, publicKey ByteSlice) Signature {
	return Signature{
		Scheme:    SchemeECDSA,
		Signature: signature,
		PublicKey: publicKey,
	}
}

// DecodeCanonicalSignature converts a []byte into a decoded structure containing both the signature and public key.
// Note: For ECDSA a pre-image must be provided to recover the public key.
func DecodeSignature(data ByteSlice, preimage ByteSlice) (Signature, error) {
	if len(data) < 1 {
		return Signature{}, ErrInvalidSignatureSize
	}

	scheme := SignatureScheme(data[0])

	switch scheme {
	case SchemeECDSA:
		return decodeECDSASignatureFromCanonicalFormat(data, preimage)
	case SchemeEdDSA:
		return decodeEdDSASignatureFromCanonicalFormat(data)
	default:
		return Signature{}, fmt.Errorf("%w: unknown scheme 0x%02x", ErrInvalidScheme, scheme)
	}
}

func decodeECDSASignatureFromCanonicalFormat(data ByteSlice, preimage ByteSlice) (Signature, error) {
	if len(data) != ECDSATotalSize {
		return Signature{}, fmt.Errorf("%w: ECDSA signature must be %d bytes, got %d", ErrInvalidSignatureSize, ECDSASignatureSize, len(data)-1)
	}

	signatureData := make([]byte, 64)
	copy(signatureData[0:64], data[1:65])
	if len(preimage) == 0 {
		return Signature{
			Scheme:    SchemeECDSA,
			Signature: signatureData,
		}, nil
	}

	if len(preimage) != 32 {
		return Signature{}, fmt.Errorf("%w: Preimage length must be %d bytes, got %d", ErrInvalidPreimageLength, Keecak256HashSize, len(preimage))
	}

	address, err := RecoverECDSASigner([32]byte(preimage), [32]byte(signatureData[0:32]), [32]byte(signatureData[32:64]))
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		Scheme:    SchemeECDSA,
		Signature: signatureData,
		PublicKey: address.Bytes(),
	}, nil
}

func decodeEdDSASignatureFromCanonicalFormat(data ByteSlice) (Signature, error) {
	if len(data) != EdDSATotalSize {
		return Signature{}, ErrInvalidSignatureSize
	}

	signatureData := make([]byte, 64)
	copy(signatureData[0:64], data[1:65])

	publicKey := make([]byte, 32)
	copy(publicKey[0:32], data[65:97])

	return Signature{
		Scheme:    SchemeEdDSA,
		Signature: signatureData,
		PublicKey: publicKey,
	}, nil
}
