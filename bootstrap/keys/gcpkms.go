package keys

import (
	"context"
	"fmt"
	"regexp"

	gcpkms "github.com/smartcontractkit/chainlink-common/keystore/gcpkms"
)

// gcpCryptoKeyNameRE matches a GCP CryptoKeyVersion resource name:
// projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>.
// The keystore requires version-qualified names: Cloud KMS rejects bare CryptoKey names on the
// asymmetric endpoints, so the configured key IDs must carry the /cryptoKeyVersions/<n> suffix.
var gcpCryptoKeyNameRE = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

// ValidateGCPKeyID checks that a configured GCP KMS key identifier is a full CryptoKeyVersion
// resource name. Cloud KMS requires version-qualified names for signing and public-key lookups, so
// a bare CryptoKey name is rejected at config time instead of at first use.
func ValidateGCPKeyID(keyID string) error {
	if !gcpCryptoKeyNameRE.MatchString(keyID) {
		return fmt.Errorf("invalid GCP CryptoKeyVersion resource name %q: must match projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>", keyID)
	}
	return nil
}

// NewGCPKMSKeystore constructs a Cloud KMS-backed keystore adapter.
//
// Credentials come exclusively from Application Default Credentials — GOOGLE_APPLICATION_CREDENTIALS
// locally (a service-account JSON or user quota project) and GKE Workload Identity, GCE
// instance/service accounts, or Cloud Run service accounts in production.
//
// nameToID maps logical key names to CryptoKeyVersion resource names
// (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>); see ValidateGCPKeyID.
//
// At startup it verifies every mapped key exists in Cloud KMS (fail-fast on missing keys or bad
// permissions).
func NewGCPKMSKeystore(ctx context.Context, nameToID map[string]string) (*KMSKeystore, error) {
	client, err := gcpkms.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud KMS client: %w", err)
	}
	return NewGCPKMSKeystoreWithClient(ctx, client, nameToID)
}

// NewGCPKMSKeystoreWithClient constructs a Cloud KMS-backed keystore adapter over an existing
// client. It exercises the same path as NewGCPKMSKeystore (real gcpkms.NewKeystore conversions and
// the newKMSKeystore wrapper), but takes the client directly, which allows tests to inject a fake.
func NewGCPKMSKeystoreWithClient(ctx context.Context, client gcpkms.Client, nameToID map[string]string) (*KMSKeystore, error) {
	inner, err := gcpkms.NewKeystore(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud KMS keystore: %w", err)
	}
	return newKMSKeystore(ctx, inner, nameToID)
}
