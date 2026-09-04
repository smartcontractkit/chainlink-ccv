package keys

import (
	"crypto/ed25519"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/corekeys/csakey"
	"github.com/smartcontractkit/chainlink-common/keystore/corekeys/ethkey"
	gcpkms "github.com/smartcontractkit/chainlink-common/keystore/gcpkms"
)

const (
	testGCPKeyRingName    = "projects/p/locations/l/keyRings/r"
	testGCPEcdsaKeyID     = testGCPKeyRingName + "/cryptoKeys/ecdsa"
	testGCPEcdsaKeyName   = testGCPEcdsaKeyID + "/cryptoKeyVersions/1"
	testGCPEd25519KeyID   = testGCPKeyRingName + "/cryptoKeys/ed25519"
	testGCPEd25519KeyName = testGCPEd25519KeyID + "/cryptoKeyVersions/1"
)

func newTestGCPKMSInner(t *testing.T, keys []gcpkms.Key) interface {
	keystore.Reader
	keystore.Signer
} {
	t.Helper()
	fakeClient, err := gcpkms.NewFakeGCPKMSClient(keys)
	require.NoError(t, err)
	inner, err := gcpkms.NewKeystore(fakeClient)
	require.NoError(t, err)
	return inner
}

func newTestGCPKMSKeystore(t *testing.T, keys []gcpkms.Key, nameToID map[string]string) *KMSKeystore {
	t.Helper()
	ks, err := newKMSKeystore(t.Context(), newTestGCPKMSInner(t, keys), nameToID)
	require.NoError(t, err)
	return ks
}

func newTestGCPECDSAKey(t *testing.T, keyID string) gcpkms.Key {
	t.Helper()
	key, err := ethkey.NewV2()
	require.NoError(t, err)
	return gcpkms.Key{
		KeyType:    keystore.ECDSA_S256,
		KeyID:      keyID,
		PrivateKey: key.Raw(),
	}
}

func newTestGCPEd25519Key(t *testing.T, keyID string) gcpkms.Key {
	t.Helper()
	key, err := csakey.NewV2()
	require.NoError(t, err)
	return gcpkms.Key{
		KeyType:    keystore.Ed25519,
		KeyID:      keyID,
		PrivateKey: key.Raw(),
	}
}

func TestGCPKMSKeystore_GetKeys_TranslatesNames(t *testing.T) {
	ks := newTestGCPKMSKeystore(t,
		[]gcpkms.Key{newTestGCPECDSAKey(t, testGCPEcdsaKeyID)},
		map[string]string{"evm/tx/my_signing_key": testGCPEcdsaKeyName},
	)

	resp, err := ks.GetKeys(t.Context(), keystore.GetKeysRequest{
		KeyNames: []string{"evm/tx/my_signing_key"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "evm/tx/my_signing_key", resp.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.ECDSA_S256, resp.Keys[0].KeyInfo.KeyType)
	require.NotEmpty(t, resp.Keys[0].KeyInfo.PublicKey)
}

func TestGCPKMSKeystore_Sign_TranslatesName(t *testing.T) {
	ks := newTestGCPKMSKeystore(t,
		[]gcpkms.Key{newTestGCPECDSAKey(t, testGCPEcdsaKeyID)},
		map[string]string{"evm/tx/my_signing_key": testGCPEcdsaKeyName},
	)

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	resp, err := ks.Sign(t.Context(), keystore.SignRequest{
		KeyName: "evm/tx/my_signing_key",
		Data:    digest,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Signature)

	keysResp, err := ks.GetKeys(t.Context(), keystore.GetKeysRequest{
		KeyNames: []string{"evm/tx/my_signing_key"},
	})
	require.NoError(t, err)
	recovered, err := crypto.Ecrecover(digest, resp.Signature)
	require.NoError(t, err)
	require.Equal(t, keysResp.Keys[0].KeyInfo.PublicKey, recovered)
}

func TestGCPKMSKeystore_Ed25519(t *testing.T) {
	ks := newTestGCPKMSKeystore(t,
		[]gcpkms.Key{newTestGCPEd25519Key(t, testGCPEd25519KeyID)},
		map[string]string{"bootstrap_default_csa_key": testGCPEd25519KeyName},
	)

	resp, err := ks.GetKeys(t.Context(), keystore.GetKeysRequest{
		KeyNames: []string{"bootstrap_default_csa_key"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "bootstrap_default_csa_key", resp.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.Ed25519, resp.Keys[0].KeyInfo.KeyType)

	sigResp, err := ks.Sign(t.Context(), keystore.SignRequest{
		KeyName: "bootstrap_default_csa_key",
		Data:    []byte("test message"),
	})
	require.NoError(t, err)
	require.Len(t, sigResp.Signature, ed25519.SignatureSize)
	require.True(t, ed25519.Verify(resp.Keys[0].KeyInfo.PublicKey, []byte("test message"), sigResp.Signature))
}

func TestGCPKMSKeystore_DisabledVersionRejected(t *testing.T) {
	key := newTestGCPECDSAKey(t, testGCPEcdsaKeyID)
	key.State = kmspb.CryptoKeyVersion_DISABLED

	_, err := newKMSKeystore(t.Context(), newTestGCPKMSInner(t, []gcpkms.Key{key}), map[string]string{
		"evm/tx/my_signing_key": testGCPEcdsaKeyName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not accessible")
}

func TestGCPKMSKeystore_BareCryptoKeyNameRejected(t *testing.T) {
	_, err := newKMSKeystore(t.Context(), newTestGCPKMSInner(t, []gcpkms.Key{
		newTestGCPECDSAKey(t, testGCPEcdsaKeyID),
	}), map[string]string{
		"evm/tx/my_signing_key": testGCPEcdsaKeyID,
	})
	require.Error(t, err)
}

func TestGCPKMSKeystore_UnmappedNameRejected(t *testing.T) {
	ks := newTestGCPKMSKeystore(t, nil, map[string]string{})

	_, err := ks.Sign(t.Context(), keystore.SignRequest{
		KeyName: testGCPEcdsaKeyName,
		Data:    make([]byte, 32),
	})
	require.ErrorIs(t, err, keystore.ErrKeyNotFound)
}

func TestGCPKMSKeystore_GetKeys_EmptyRequestListsOnlyMappedKeys(t *testing.T) {
	ks := newTestGCPKMSKeystore(t, []gcpkms.Key{
		newTestGCPECDSAKey(t, testGCPEcdsaKeyID),
		newTestGCPEd25519Key(t, testGCPEd25519KeyID),
		newTestGCPECDSAKey(t, testGCPKeyRingName+"/cryptoKeys/unrelated"),
	}, map[string]string{
		"evm/tx/my_signing_key": testGCPEcdsaKeyName,
	})

	resp, err := ks.GetKeys(t.Context(), keystore.GetKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "evm/tx/my_signing_key", resp.Keys[0].KeyInfo.Name)
}
