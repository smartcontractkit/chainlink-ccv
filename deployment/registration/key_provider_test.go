package registration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/info"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestStaticCSAKeyProvider(t *testing.T) {
	t.Parallel()
	t.Run("returns key", func(t *testing.T) {
		t.Parallel()
		key, err := StaticCSAKeyProvider("abc").CSAKey(t.Context())
		require.NoError(t, err)
		require.Equal(t, "abc", key)
	})
	t.Run("rejects empty key", func(t *testing.T) {
		t.Parallel()
		_, err := StaticCSAKeyProvider(" ").CSAKey(t.Context())
		require.ErrorContains(t, err, "empty")
	})
}

func TestInfoServerCSAKeyProvider(t *testing.T) {
	t.Parallel()
	raw := []byte{1, 2, 3, 4}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeKeyResponse(t, w, []keystore.GetKeyResponse{{KeyInfo: keystore.KeyInfo{
			Name: info.DefaultCSAKeyName, PublicKey: raw,
		}}})
	}))
	defer server.Close()

	key, err := (InfoServerCSAKeyProvider{URL: server.URL}).CSAKey(t.Context())
	require.NoError(t, err)
	require.Equal(t, "01020304", key)
}

func writeKeyResponse(t *testing.T, w http.ResponseWriter, keys []keystore.GetKeyResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keystore.GetKeysResponse{Keys: keys}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
