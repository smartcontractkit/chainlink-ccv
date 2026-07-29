package shared

import (
	"fmt"
	"sort"
	"strings"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// CanonicalEVMAddress returns addr lowercased and 0x-prefixed.
//
// JD stores an OCR key bundle's OnchainSigningAddress as bare hex, with no prefix. Consumers do not
// all tolerate that: a CL node decodes the signer_address in a ccvcommitteeverifier job spec with
// hexutil.Decode, which rejects a string without 0x and fails job creation. Producing the canonical
// form at every point an address leaves this package keeps that from depending on a caller
// remembering to normalize.
//
// It is idempotent, so applying it to an already-canonical address is safe.
func CanonicalEVMAddress(addr string) string {
	lower := strings.ToLower(addr)
	if !strings.HasPrefix(lower, "0x") {
		return "0x" + lower
	}
	return lower
}

// SigningIdentityReader returns the family-appropriate signer identity from a JD
// OCRKeyBundle. Families that need OnchainSigningPubKey instead of the default
// OnchainSigningAddress register a reader at init time.
type SigningIdentityReader interface {
	// FromBundle returns the family-appropriate signer identity from a JD OCRKeyBundle.
	FromBundle(bundle *nodev1.OCR2Config_OCRKeyBundle) (string, error)
}

// EVMSigningIdentityReader reads OnchainSigningAddress — the 20-byte EVM-derived
// address. This is the default; families with different identity formats register
// their own reader.
type EVMSigningIdentityReader struct{}

func (EVMSigningIdentityReader) FromBundle(b *nodev1.OCR2Config_OCRKeyBundle) (string, error) {
	if b == nil {
		return "", fmt.Errorf("nil OCR key bundle")
	}
	if b.OnchainSigningAddress == "" {
		return "", fmt.Errorf("OnchainSigningAddress is empty")
	}
	// Canonicalise here rather than relying on a normalizer being registered for the family. The
	// two registries are populated by the same init(), so in principle either implies the other,
	// but a reader that returns a raw address makes correctness depend on the caller applying
	// NormalizeAddress afterwards — and a missed call surfaces only as a CL node refusing to create
	// the verifier job, with nothing in the log pointing back here.
	return CanonicalEVMAddress(b.OnchainSigningAddress), nil
}

var signingIdentityReaders = make(map[string]SigningIdentityReader)

// RegisterSigningIdentityReader associates a chain family with its SigningIdentityReader.
// Called from init() in chain-specific adapter packages.
func RegisterSigningIdentityReader(family string, reader SigningIdentityReader) {
	signingIdentityReaders[family] = reader
}

// SigningIdentityFromBundle returns the signer identity for the given chain family
// from a JD OCRKeyBundle. If the family has registered a reader, that reader is used;
// otherwise the default — OnchainSigningAddress (the EVM-derived address) — is returned.
//
// The result is normalized either way. A reader chooses which field of the bundle carries the
// family's identity, not whether the result is canonical, so registering one must not change the
// form of the address a caller gets back.
func SigningIdentityFromBundle(family string, bundle *nodev1.OCR2Config_OCRKeyBundle) (string, error) {
	if reader, ok := signingIdentityReaders[family]; ok {
		identity, err := reader.FromBundle(bundle)
		if err != nil {
			return "", err
		}
		return NormalizeAddress(family, identity), nil
	}
	if bundle == nil {
		return "", fmt.Errorf("nil OCR key bundle")
	}
	if bundle.OnchainSigningAddress == "" {
		return "", fmt.Errorf("OnchainSigningAddress is empty")
	}
	return NormalizeAddress(family, bundle.OnchainSigningAddress), nil
}

// RegisteredSigningIdentityFamilies returns the families that have registered a
// SigningIdentityReader, in sorted order.
func RegisteredSigningIdentityFamilies() []string {
	families := make([]string, 0, len(signingIdentityReaders))
	for f := range signingIdentityReaders {
		families = append(families, f)
	}
	sort.Strings(families)
	return families
}
