package hashing

// CalculateSignatureHash calculates the hash that should be signed for message verification.
// In CCIP v1.7, this is simply the messageHash itself hashed again (no verifierBlob concatenation needed).
func CalculateSignatureHash(messageHash [32]byte) [32]byte {
	return messageHash
}
