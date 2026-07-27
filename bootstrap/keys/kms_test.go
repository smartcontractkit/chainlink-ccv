package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/kms"
)

// mockKMSClient implements the chainlink-common kms.Client interface for testing.
type mockKMSClient struct {
	keys map[string]*mockKey
}

type mockKey struct {
	keyID   string
	keyType keystore.KeyType
	privKey any
}

func newMockKMSClient() *mockKMSClient {
	return &mockKMSClient{keys: make(map[string]*mockKey)}
}

func (m *mockKMSClient) addECDSAKey(keyID string) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	m.keys[keyID] = &mockKey{keyID: keyID, keyType: keystore.ECDSA_S256, privKey: privKey}
}

func (m *mockKMSClient) addEd25519Key(keyID string) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	m.keys[keyID] = &mockKey{keyID: keyID, keyType: keystore.Ed25519, privKey: privKey}
}

func (m *mockKMSClient) GetPublicKey(_ context.Context, input *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	k, ok := m.keys[*input.KeyId]
	if !ok {
		return nil, errors.New("key not found")
	}
	var pubKeyBytes []byte
	switch k.keyType {
	case keystore.ECDSA_S256:
		privKey := k.privKey.(*ecdsa.PrivateKey)
		// AWS KMS returns the public key ASN.1-DER encoded; mirror that.
		asn1PubKey, err := kms.SEC1ToASN1PublicKey(crypto.FromECDSAPub(&privKey.PublicKey))
		if err != nil {
			return nil, err
		}
		pubKeyBytes = asn1PubKey
	case keystore.Ed25519:
		privKey := k.privKey.(ed25519.PrivateKey)
		pub := privKey.Public().(ed25519.PublicKey)
		var err error
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
	}
	return &awskms.GetPublicKeyOutput{
		KeyId:     &k.keyID,
		PublicKey: pubKeyBytes,
	}, nil
}

func (m *mockKMSClient) DescribeKey(_ context.Context, input *awskms.DescribeKeyInput, _ ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error) {
	k, ok := m.keys[*input.KeyId]
	if !ok {
		return nil, errors.New("key not found")
	}
	var keySpec kmstypes.KeySpec
	switch k.keyType {
	case keystore.ECDSA_S256:
		keySpec = kmstypes.KeySpecEccSecgP256k1
	case keystore.Ed25519:
		keySpec = kmstypes.KeySpecEccNistEdwards25519
	}
	now := time.Now()
	return &awskms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId:        &k.keyID,
			KeySpec:      keySpec,
			CreationDate: &now,
		},
	}, nil
}

func (m *mockKMSClient) Sign(_ context.Context, input *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	k, ok := m.keys[*input.KeyId]
	if !ok {
		return nil, errors.New("key not found")
	}
	var sig []byte
	switch k.keyType {
	case keystore.ECDSA_S256:
		privKey := k.privKey.(*ecdsa.PrivateKey)
		// crypto.Sign expects a 32-byte digest and returns a 65-byte SEC1 recoverable signature;
		// AWS KMS returns it ASN.1-DER encoded, so re-encode to mirror real KMS output.
		sec1Sig, err := crypto.Sign(input.Message, privKey)
		if err != nil {
			return nil, err
		}
		sig, err = kms.SEC1ToASN1Sig(sec1Sig)
		if err != nil {
			return nil, err
		}
	case keystore.Ed25519:
		privKey := k.privKey.(ed25519.PrivateKey)
		sig = ed25519.Sign(privKey, input.Message)
	}
	return &awskms.SignOutput{
		KeyId:     &k.keyID,
		Signature: sig,
	}, nil
}

func (m *mockKMSClient) ListKeys(_ context.Context, _ *awskms.ListKeysInput, _ ...func(*awskms.Options)) (*awskms.ListKeysOutput, error) {
	entries := make([]kmstypes.KeyListEntry, 0, len(m.keys))
	for _, k := range m.keys {
		keyID := k.keyID
		entries = append(entries, kmstypes.KeyListEntry{KeyId: &keyID})
	}
	return &awskms.ListKeysOutput{Keys: entries}, nil
}

// newTestKMSKeystore builds a KMSKeystore over the REAL chainlink-common kms.NewKeystore, backed by
// the mock client — so name translation, key-spec mapping, and ASN.1/SEC1 decoding are all exercised.
func newTestKMSKeystore(t *testing.T, client *mockKMSClient, nameToID map[string]string) *KMSKeystore {
	t.Helper()
	inner, err := kms.NewKeystore(client)
	require.NoError(t, err)
	ks, err := newKMSKeystore(context.Background(), inner, nameToID)
	require.NoError(t, err)
	return ks
}

func TestKMSKeystore_GetKeys_TranslatesNames(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("kms-ecdsa-id")

	ks := newTestKMSKeystore(t, client, map[string]string{"evm/tx/my_signing_key": "kms-ecdsa-id"})

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{
		KeyNames: []string{"evm/tx/my_signing_key"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "evm/tx/my_signing_key", resp.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.ECDSA_S256, resp.Keys[0].KeyInfo.KeyType)
	require.NotEmpty(t, resp.Keys[0].KeyInfo.PublicKey)
}

func TestKMSKeystore_Sign_TranslatesName(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("kms-ecdsa-id")

	ks := newTestKMSKeystore(t, client, map[string]string{"evm/tx/my_signing_key": "kms-ecdsa-id"})

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	resp, err := ks.Sign(context.Background(), keystore.SignRequest{
		KeyName: "evm/tx/my_signing_key",
		Data:    digest,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Signature)
}

func TestKMSKeystore_Verify_Delegates(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	ks := newTestKMSKeystore(t, client, map[string]string{})

	_, err := ks.Verify(context.Background(), keystore.VerifyRequest{
		KeyType:   keystore.Ed25519,
		PublicKey: make([]byte, 32),
		Data:      []byte("test"),
		Signature: make([]byte, 64),
	})
	require.NoError(t, err)
}

func TestKMSKeystore_AdminReturnsUnimplemented(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	ks := newTestKMSKeystore(t, client, map[string]string{})

	ctx := context.Background()

	_, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.DeleteKeys(ctx, keystore.DeleteKeysRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.ExportKeys(ctx, keystore.ExportKeysRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.SetMetadata(ctx, keystore.SetMetadataRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.RenameKey(ctx, keystore.RenameKeyRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)
}

func TestKMSKeystore_EncryptorReturnsUnimplemented(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	ks := newTestKMSKeystore(t, client, map[string]string{})

	ctx := context.Background()

	_, err := ks.Encrypt(ctx, keystore.EncryptRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.Decrypt(ctx, keystore.DecryptRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)

	_, err = ks.DeriveSharedSecret(ctx, keystore.DeriveSharedSecretRequest{})
	require.ErrorIs(t, err, keystore.ErrUnimplemented)
}

func TestKMSKeystore_GetKeys_EmptyRequestReturnsOnlyMappedKeys(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("kms-ecdsa-id")
	client.addEd25519Key("kms-ed25519-id")
	client.addECDSAKey("unmapped-key")

	ks := newTestKMSKeystore(t, client, map[string]string{
		"my_ecdsa_key": "kms-ecdsa-id",
		"my_ed_key":    "kms-ed25519-id",
	})

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 2)

	names := map[string]bool{}
	for _, k := range resp.Keys {
		names[k.KeyInfo.Name] = true
	}
	require.True(t, names["my_ecdsa_key"])
	require.True(t, names["my_ed_key"])
}

func TestKMSKeystore_GetKeys_EmptyRequestWithNoMappingReturnsEmpty(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("kms-ecdsa-id")

	ks := newTestKMSKeystore(t, client, map[string]string{})

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{})
	require.NoError(t, err)
	require.Empty(t, resp.Keys)
}

func TestKMSKeystore_GetKeys_UnmappedNamePassesThrough(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("some-kms-id")

	ks := newTestKMSKeystore(t, client, map[string]string{})

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{
		KeyNames: []string{"some-kms-id"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "some-kms-id", resp.Keys[0].KeyInfo.Name)
}

func TestKMSKeystore_Sign_UnmappedNamePassesThrough(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("direct-key-id")

	ks := newTestKMSKeystore(t, client, map[string]string{})

	digest := make([]byte, 32)
	resp, err := ks.Sign(context.Background(), keystore.SignRequest{
		KeyName: "direct-key-id",
		Data:    digest,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Signature)
}

func TestKMSKeystore_Ed25519(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addEd25519Key("kms-ed25519-id")

	ks := newTestKMSKeystore(t, client, map[string]string{"bootstrap_default_csa_key": "kms-ed25519-id"})

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{
		KeyNames: []string{"bootstrap_default_csa_key"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	require.Equal(t, "bootstrap_default_csa_key", resp.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.Ed25519, resp.Keys[0].KeyInfo.KeyType)

	sigResp, err := ks.Sign(context.Background(), keystore.SignRequest{
		KeyName: "bootstrap_default_csa_key",
		Data:    []byte("test message"),
	})
	require.NoError(t, err)
	require.Len(t, sigResp.Signature, 64)
}

func TestKMSKeystore_VerifyKeysExist(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("existing-key")

	// newKMSKeystore runs verifyKeys; a mapped-and-present key must succeed.
	ks := newTestKMSKeystore(t, client, map[string]string{"my_key": "existing-key"})
	require.NoError(t, ks.verifyKeys(context.Background()))
}

func TestKMSKeystore_VerifyKeysExist_FailsOnMissingKey(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	inner, err := kms.NewKeystore(client)
	require.NoError(t, err)

	// A mapped key that does not exist in KMS must fail construction (fail-fast).
	_, err = newKMSKeystore(context.Background(), inner, map[string]string{"my_key": "nonexistent-key"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonexistent-key")
	require.Contains(t, err.Error(), "my_key")
}

func TestKMSKeystore_DuplicateKeyIDFails(t *testing.T) {
	t.Parallel()

	client := newMockKMSClient()
	client.addECDSAKey("shared-key-id")

	inner, err := kms.NewKeystore(client)
	require.NoError(t, err)

	_, err = newKMSKeystore(context.Background(), inner, map[string]string{
		"key_a": "shared-key-id",
		"key_b": "shared-key-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "shared-key-id")
	require.Contains(t, err.Error(), "key_a")
	require.Contains(t, err.Error(), "key_b")
}
