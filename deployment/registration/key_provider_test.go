package registration

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
			Name: DefaultCSAKeyName, PublicKey: raw,
		}}})
	}))
	defer server.Close()

	key, err := (InfoServerCSAKeyProvider{URL: server.URL}).CSAKey(t.Context())
	require.NoError(t, err)
	require.Equal(t, "01020304", key)
}

func TestFetchPublicKeysByName(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != GetKeysEndpoint {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeKeyResponse(t, w, []keystore.GetKeyResponse{
			{KeyInfo: keystore.KeyInfo{Name: "key-a", PublicKey: []byte{1}}},
			{KeyInfo: keystore.KeyInfo{Name: "key-b", PublicKey: []byte{2, 3}}},
		})
	}))
	defer server.Close()

	keys, err := FetchPublicKeys(t.Context(), nil, server.URL, "key-b", "key-a")
	require.NoError(t, err)
	require.Equal(t, []byte{1}, keys["key-a"])
	require.Equal(t, []byte{2, 3}, keys["key-b"])
}

func TestFetchPublicKeysErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			name: "HTTP status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			want: "unexpected HTTP status 401",
		},
		{
			name: "malformed JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not-json"))
			},
			want: "decode key response",
		},
		{
			name: "missing requested key",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeKeyResponse(t, w, []keystore.GetKeyResponse{{KeyInfo: keystore.KeyInfo{Name: "other", PublicKey: []byte{1}}}})
			},
			want: "not found",
		},
		{
			name: "duplicate key",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeKeyResponse(t, w, []keystore.GetKeyResponse{
					{KeyInfo: keystore.KeyInfo{Name: "key-a", PublicKey: []byte{1}}},
					{KeyInfo: keystore.KeyInfo{Name: "key-a", PublicKey: []byte{2}}},
				})
			},
			want: "duplicate key",
		},
		{
			name: "empty public key",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeKeyResponse(t, w, []keystore.GetKeyResponse{{KeyInfo: keystore.KeyInfo{Name: "key-a"}}})
			},
			want: "empty public key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			_, err := FetchPublicKeys(t.Context(), nil, server.URL, "key-a")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestFetchPublicKeysRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	_, err := FetchPublicKeys(t.Context(), nil, "http://node.test")
	require.ErrorContains(t, err, "at least one key name")

	for _, rawURL := range []string{"", "ftp://node.test", "http://user:pass@node.test", "http://node.test?x=1", "http://node.test#fragment"} {
		_, err := FetchPublicKeys(t.Context(), nil, rawURL, "key-a")
		require.Error(t, err, rawURL)
	}
}

func TestFetchPublicKeysTransportAndTimeout(t *testing.T) {
	t.Parallel()
	t.Run("transport error", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})}
		_, err := FetchPublicKeys(t.Context(), client, "http://node.test", "key-a")
		require.ErrorContains(t, err, "dial failed")
	})
	t.Run("client timeout", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}))
		defer server.Close()
		client := &http.Client{Timeout: 20 * time.Millisecond}
		start := time.Now()
		_, err := FetchPublicKeys(t.Context(), client, server.URL, "key-a")
		require.Error(t, err)
		require.Less(t, time.Since(start), time.Second)
	})
}

func TestFetchPublicKeysResponseLimit(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxKeyResponseBytes+1))
	}))
	defer server.Close()
	_, err := FetchPublicKeys(t.Context(), nil, server.URL, "key-a")
	require.ErrorContains(t, err, "exceeds")
}

func writeKeyResponse(t *testing.T, w http.ResponseWriter, keys []keystore.GetKeyResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keystore.GetKeysResponse{Keys: keys}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
