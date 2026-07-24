package keys

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/kms"
)

// signerReader is the subset of keystore.Keystore that a KMS backend implements
type signerReader interface {
	keystore.Reader
	keystore.Signer
}

// KMSKeystore wraps a chainlink-common KMS keystore with logical-name translation.
//
// Callers reference keys by logical name (e.g. "bootstrap_default_csa_key"); the adapter
// translates to KMS Key IDs on the way in and relabels responses on the way out, so
// downstream code (CSASigner, buildUpdateNodeRequest, accessors, info server) is unchanged.
// (Admin + Encryptor return ErrUnimplemented) and overriding GetKeys, Sign, and Verify.
type KMSKeystore struct {
	keystore.UnimplementedKeystore
	inner    signerReader
	nameToID map[string]string
	idToName map[string]string
}

var _ keystore.Keystore = (*KMSKeystore)(nil)

// NewKMSKeystore constructs a KMS-backed keystore adapter.
//
//   - profile: AWS shared-config profile (empty => default credential chain / IRSA)
//   - region: AWS region (empty => from profile or environment)
//   - nameToID: maps logical key names to KMS Key IDs
//
// At startup it verifies every mapped key exists in KMS (fail-fast on missing keys or bad permissions).
func NewKMSKeystore(ctx context.Context, profile, region string, nameToID map[string]string) (*KMSKeystore, error) {
	client, err := kms.NewClient(ctx, kms.ClientOptions{
		Profile: profile,
		Region:  region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	inner, err := kms.NewKeystore(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS keystore: %w", err)
	}
	return newKMSKeystore(ctx, inner, nameToID)
}

// newKMSKeystore wraps an existing Reader+Signer with logical-name translation and verifies that
// every mapped key exists.
func newKMSKeystore(ctx context.Context, inner signerReader, nameToID map[string]string) (*KMSKeystore, error) {
	idToName := make(map[string]string, len(nameToID))
	for name, id := range nameToID {
		if existing, ok := idToName[id]; ok {
			return nil, fmt.Errorf("KMS key ID %q is mapped to both %q and %q: each key ID must map to exactly one logical name", id, existing, name)
		}
		idToName[id] = name
	}

	ks := &KMSKeystore{
		inner:    inner,
		nameToID: nameToID,
		idToName: idToName,
	}

	if err := ks.verifyKeys(ctx); err != nil {
		return nil, err
	}
	return ks, nil
}

// verifyKeys checks that every mapped KMS key exists and is accessible.
func (k *KMSKeystore) verifyKeys(ctx context.Context) error {
	for name, id := range k.nameToID {
		_, err := k.inner.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{id}})
		if err != nil {
			return fmt.Errorf("KMS key %q (logical name %q) not accessible: %w", id, name, err)
		}
	}
	return nil
}

// GetKeys translates logical key names to KMS Key IDs, delegates to the inner KMS keystore,
// and relabels the response key names back to logical names.
//
// When KeyNames is empty, only the keys in the name map are returned not all KMS keys in the
// account.
func (k *KMSKeystore) GetKeys(ctx context.Context, req keystore.GetKeysRequest) (keystore.GetKeysResponse, error) {
	if len(req.KeyNames) == 0 {
		allIDs := make([]string, 0, len(k.idToName))
		for id := range k.idToName {
			allIDs = append(allIDs, id)
		}
		if len(allIDs) == 0 {
			return keystore.GetKeysResponse{}, nil
		}
		resp, err := k.inner.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: allIDs})
		if err != nil {
			return resp, err
		}
		for i := range resp.Keys {
			if friendly, ok := k.idToName[resp.Keys[i].KeyInfo.Name]; ok {
				resp.Keys[i].KeyInfo.Name = friendly
			}
		}
		return resp, nil
	}

	translated := make([]string, len(req.KeyNames))
	for i, name := range req.KeyNames {
		if id, ok := k.nameToID[name]; ok {
			translated[i] = id
		} else {
			translated[i] = name
		}
	}

	resp, err := k.inner.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: translated})
	if err != nil {
		return resp, err
	}

	for i := range resp.Keys {
		if friendly, ok := k.idToName[resp.Keys[i].KeyInfo.Name]; ok {
			resp.Keys[i].KeyInfo.Name = friendly
		}
	}
	return resp, nil
}

// Sign translates the logical key name to a KMS Key ID and delegates signing.
func (k *KMSKeystore) Sign(ctx context.Context, req keystore.SignRequest) (keystore.SignResponse, error) {
	if id, ok := k.nameToID[req.KeyName]; ok {
		req.KeyName = id
	}
	return k.inner.Sign(ctx, req)
}

// Verify delegates directly. VerifyRequest has no key name field.
func (k *KMSKeystore) Verify(ctx context.Context, req keystore.VerifyRequest) (keystore.VerifyResponse, error) {
	return k.inner.Verify(ctx, req)
}
