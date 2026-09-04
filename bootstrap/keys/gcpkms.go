package keys

import (
	"context"
	"fmt"

	"google.golang.org/api/option"

	gcpkms "github.com/smartcontractkit/chainlink-common/keystore/gcpkms"
)

// NewGCPKMSKeystore constructs a Cloud KMS-backed keystore adapter.
//
//   - credentialsFile: path to a GCP service account JSON key. Local development only — leave empty
//     in production, where credentials come from Application Default Credentials (GKE Workload
//     Identity, GCE instance/service accounts, or GOOGLE_APPLICATION_CREDENTIALS).
//   - nameToID: maps logical key names to CryptoKeyVersion resource names
//     (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>). Cloud KMS
//     requires version-qualified names for signing and public-key lookups; rotating a key means
//     configuring the new version's resource name.
//
// At startup it verifies every mapped key exists in Cloud KMS (fail-fast on missing keys or bad
// permissions).
func NewGCPKMSKeystore(ctx context.Context, credentialsFile string, nameToID map[string]string) (*KMSKeystore, error) {
	var opts []option.ClientOption
	if credentialsFile != "" {
		opts = append(opts, option.WithAuthCredentialsFile(option.ServiceAccount, credentialsFile))
	}
	client, err := gcpkms.NewClient(ctx, opts...)
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
