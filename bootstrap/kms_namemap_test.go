package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestBuildKMSNameMap(t *testing.T) {
	t.Parallel()

	cfg := KMSKeystoreConfig{
		Provider:     KMSProviderAWS,
		EcdsaKeyID:   "ecdsa-id",
		Ed25519KeyID: "ed25519-id",
	}

	t.Run("distinct types map to their configured key IDs", func(t *testing.T) {
		t.Parallel()
		got, err := buildKMSNameMap(cfg, []keyToInit{
			{name: "csa", purpose: "csa", keyType: keystore.Ed25519},
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"csa": "ed25519-id", "signing": "ecdsa-id"}, got)
	})

	t.Run("ecdsa-only keys need no ed25519 key ID", func(t *testing.T) {
		t.Parallel()
		// The local-mode KMS shape: no CSA key declared, so ed25519_key_id is not required.
		got, err := buildKMSNameMap(KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-id"}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"signing": "ecdsa-id"}, got)
	})

	t.Run("missing key ID for a declared type errors", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{Provider: KMSProviderAWS, Ed25519KeyID: "ed25519-id"}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa_key_id is required")
	})

	t.Run("two keys of the same type collide with a dedicated error", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(cfg, []keyToInit{
			{name: "signing-a", purpose: "signing", keyType: keystore.ECDSA_S256},
			{name: "signing-b", purpose: "transmitting", keyType: keystore.ECDSA_S256},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "both resolve to KMS Key ID")
		require.Contains(t, err.Error(), "signing-a")
		require.Contains(t, err.Error(), "signing-b")
	})

	t.Run("same key ID reused across types collides", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "shared", Ed25519KeyID: "shared"}, []keyToInit{
			{name: "csa", purpose: "csa", keyType: keystore.Ed25519},
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "both resolve to KMS Key ID")
	})

	t.Run("gcp provider accepts full CryptoKeyVersion resource names", func(t *testing.T) {
		t.Parallel()
		gcpCfg := KMSKeystoreConfig{
			Provider:     KMSProviderGCP,
			EcdsaKeyID:   "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1",
			Ed25519KeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/ed25519/cryptoKeyVersions/1",
		}
		got, err := buildKMSNameMap(gcpCfg, []keyToInit{
			{name: "csa", purpose: "csa", keyType: keystore.Ed25519},
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, map[string]string{
			"csa":     "projects/p/locations/l/keyRings/r/cryptoKeys/ed25519/cryptoKeyVersions/1",
			"signing": "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa/cryptoKeyVersions/1",
		}, got)
	})

	t.Run("gcp provider rejects malformed resource names", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider:   KMSProviderGCP,
			EcdsaKeyID: "not-a-resource-name",
		}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid GCP CryptoKeyVersion resource name")
	})

	t.Run("gcp provider rejects bare CryptoKey name (version required)", func(t *testing.T) {
		t.Parallel()
		// Cloud KMS rejects bare CryptoKey names on the asymmetric endpoints, so a key ID that
		// omits /cryptoKeyVersions/<n> must be rejected at config time.
		_, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider:   KMSProviderGCP,
			EcdsaKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/ecdsa",
		}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid GCP CryptoKeyVersion resource name")
	})

	t.Run("aws provider ignores resource-name validation", func(t *testing.T) {
		t.Parallel()
		// AWS accepts Key IDs or ARNs; a bare id must not be rejected by GCP-style validation.
		got, err := buildKMSNameMap(KMSKeystoreConfig{Provider: KMSProviderAWS, EcdsaKeyID: "ecdsa-id"}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"signing": "ecdsa-id"}, got)
	})

	t.Run("key_ids map two keys of one type to distinct KMS keys", func(t *testing.T) {
		t.Parallel()
		cfg := KMSKeystoreConfig{
			Provider: KMSProviderAWS,
			KeyIDs: map[string]string{
				"signing-a": "ecdsa-a",
				"signing-b": "ecdsa-b",
			},
		}
		got, err := buildKMSNameMap(cfg, []keyToInit{
			{name: "signing-a", purpose: "signing", keyType: keystore.ECDSA_S256},
			{name: "signing-b", purpose: "transmitting", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, cfg.KeyIDs, got)
		require.Equal(t, map[string]string{"signing-a": "ecdsa-a", "signing-b": "ecdsa-b"}, cfg.KeyIDs)
	})

	t.Run("key_ids override the type default only for the named key", func(t *testing.T) {
		t.Parallel()
		got, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider:   KMSProviderAWS,
			EcdsaKeyID: "ecdsa-default",
			KeyIDs:     map[string]string{"signing-b": "ecdsa-b"},
		}, []keyToInit{
			{name: "signing-a", purpose: "signing", keyType: keystore.ECDSA_S256},
			{name: "signing-b", purpose: "transmitting", keyType: keystore.ECDSA_S256},
		})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"signing-a": "ecdsa-default", "signing-b": "ecdsa-b"}, got)
	})

	t.Run("key_ids entry for an undeclared key errors", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider:   KMSProviderAWS,
			EcdsaKeyID: "ecdsa-id",
			KeyIDs:     map[string]string{"typo": "other"},
		}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.ErrorContains(t, err, "matches no key")
		require.ErrorContains(t, err, "typo")
	})

	t.Run("empty override does not fall back to the type default", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider:   KMSProviderAWS,
			EcdsaKeyID: "ecdsa-default",
			KeyIDs:     map[string]string{"signing": ""},
		}, []keyToInit{
			{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256},
		})
		require.ErrorContains(t, err, `key_ids entry "signing"`)
		require.ErrorContains(t, err, "is required")
	})

	t.Run("named IDs cannot collide with another named ID or a default", func(t *testing.T) {
		t.Parallel()
		for _, keyIDs := range []map[string]string{
			{"signing-a": "shared", "signing-b": "shared"},
			{"signing-b": "shared"},
		} {
			_, err := buildKMSNameMap(KMSKeystoreConfig{
				Provider:   KMSProviderAWS,
				EcdsaKeyID: "shared",
				KeyIDs:     keyIDs,
			}, []keyToInit{
				{name: "signing-a", purpose: "signing", keyType: keystore.ECDSA_S256},
				{name: "signing-b", purpose: "transmitting", keyType: keystore.ECDSA_S256},
			})
			require.ErrorContains(t, err, "both resolve to KMS Key ID")
		}
	})

	t.Run("gcp named IDs require CryptoKeyVersion resource names", func(t *testing.T) {
		t.Parallel()
		const id = "projects/p/locations/l/keyRings/r/cryptoKeys/signing/cryptoKeyVersions/1"
		cfg := KMSKeystoreConfig{
			Provider: KMSProviderGCP,
			KeyIDs:   map[string]string{"signing": id},
		}
		required := []keyToInit{{name: "signing", purpose: "signing", keyType: keystore.ECDSA_S256}}
		got, err := buildKMSNameMap(cfg, required)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"signing": id}, got)

		cfg.KeyIDs["signing"] = "not-a-resource-name"
		_, err = buildKMSNameMap(cfg, required)
		require.ErrorContains(t, err, "invalid GCP CryptoKeyVersion resource name")
	})

	t.Run("named IDs do not enable unsupported declared types", func(t *testing.T) {
		t.Parallel()
		_, err := buildKMSNameMap(KMSKeystoreConfig{
			Provider: KMSProviderAWS,
			KeyIDs:   map[string]string{"signing": "key-id"},
		}, []keyToInit{{name: "signing", purpose: "signing", keyType: keystore.X25519}})
		require.ErrorContains(t, err, "KMS does not support key type")
	})
}
