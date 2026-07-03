package shared

import (
	"fmt"
	"strings"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// SigningIdentityReader overrides SigningIdentityFromBundle when the native identity is
// not OCRKeyBundle.OnchainSigningAddress. Registered from chain product init().
type SigningIdentityReader interface {
	FromBundle(bundle *nodev1.OCR2Config_OCRKeyBundle) (string, error)
}

var signingIdentityReaders = map[string]SigningIdentityReader{}

func RegisterSigningIdentityReader(family string, reader SigningIdentityReader) {
	signingIdentityReaders[family] = reader
}

// SigningIdentityFromBundle uses a registered family reader, or OnchainSigningAddress.
func SigningIdentityFromBundle(family string, bundle *nodev1.OCR2Config_OCRKeyBundle) (string, error) {
	if reader, ok := signingIdentityReaders[family]; ok {
		return reader.FromBundle(bundle)
	}
	if bundle == nil {
		return "", fmt.Errorf("nil OCR key bundle")
	}
	addr := strings.TrimSpace(bundle.OnchainSigningAddress)
	if addr == "" {
		return "", fmt.Errorf("missing onchain_signing_address")
	}
	return NormalizeAddress(family, addr), nil
}
