package migration

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

// fakeNode is an httptest.Server scripted with the node API responses a test wants. The export
// endpoints encrypt on the fly with the newpassword the caller requested, which is what the real
// node does — so the files an export produces here are indistinguishable from a live node's.
//
// Handlers run on server goroutines, so anything a test asserts on afterwards is behind the
// mutex or atomic, and handlers never call require: a failure is reported as an HTTP error for
// the client to surface instead.
type fakeNode struct {
	t *testing.T

	email, password string
	cookieValue     string

	ocr2BundlesJSON string // raw elements of the "data" array for GET /v2/keys/ocr2
	ethKeysJSON     string // ... for GET /v2/keys/eth
	jobsJSON        string // ... for GET /v2/jobs

	// ocr2Key and ethKey are the key material the export endpoints encrypt, independent of what
	// the listings claim — so a test can make the export disagree with the listing.
	ocr2Key *ecdsa.PrivateKey
	ethKey  *ecdsa.PrivateKey

	sawSessionCookie atomic.Bool

	mu              sync.Mutex
	lastNewPassword string
}

func newFakeNode(t *testing.T) *fakeNode {
	return &fakeNode{
		t:           t,
		email:       "admin@example.com",
		password:    "node-api-password",
		cookieValue: "test-session-id",
	}
}

func (n *fakeNode) start() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"errors":[{"detail":"malformed login"}]}`, http.StatusBadRequest)
			return
		}
		if req.Email != n.email || req.Password != n.password {
			http.Error(w, `{"errors":[{"detail":"invalid email or password"}]}`, http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "clsession", Value: n.cookieValue, Path: "/"})
		_, _ = fmt.Fprint(w, `{"data":{"type":"session","id":"1","attributes":{"authenticated":true}}}`)
	})
	mux.HandleFunc("/v2/keys/ocr2", func(w http.ResponseWriter, r *http.Request) {
		if !n.checkCookie(w, r) {
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":[%s]}`, n.ocr2BundlesJSON)
	})
	mux.HandleFunc("/v2/keys/eth", func(w http.ResponseWriter, r *http.Request) {
		if !n.checkCookie(w, r) {
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":[%s]}`, n.ethKeysJSON)
	})
	mux.HandleFunc("/v2/jobs", func(w http.ResponseWriter, r *http.Request) {
		if !n.checkCookie(w, r) {
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":[%s]}`, n.jobsJSON)
	})
	mux.HandleFunc("/v2/keys/ocr2/export/", func(w http.ResponseWriter, r *http.Request) {
		if !n.checkCookie(w, r) {
			return
		}
		password := n.recordNewPassword(w, r)
		if password == "" {
			return
		}
		_, _ = w.Write(encryptOCR2Export(n.ocr2Key, password))
	})
	mux.HandleFunc("/v2/keys/eth/export/", func(w http.ResponseWriter, r *http.Request) {
		if !n.checkCookie(w, r) {
			return
		}
		password := n.recordNewPassword(w, r)
		if password == "" {
			return
		}
		_, _ = w.Write(encryptETHExport(n.ethKey, password))
	})
	srv := httptest.NewServer(mux)
	n.t.Cleanup(srv.Close)
	return srv
}

// checkCookie enforces the session the same way the node does: no valid clsession cookie, no API.
func (n *fakeNode) checkCookie(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("clsession")
	if err != nil || cookie.Value != n.cookieValue {
		http.Error(w, `{"errors":[{"detail":"not authenticated"}]}`, http.StatusUnauthorized)
		return false
	}
	n.sawSessionCookie.Store(true)
	return true
}

func (n *fakeNode) recordNewPassword(w http.ResponseWriter, r *http.Request) string {
	password := r.URL.Query().Get("newpassword")
	if password == "" {
		http.Error(w, `{"errors":[{"detail":"newpassword is required"}]}`, http.StatusBadRequest)
		return ""
	}
	n.mu.Lock()
	n.lastNewPassword = password
	n.mu.Unlock()
	return password
}

func (n *fakeNode) getLastNewPassword() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastNewPassword
}

func ocr2BundleJSON(id, chainType string) string {
	return fmt.Sprintf(
		`{"id":%q,"type":"offChainReporting2KeyBundle","attributes":{"chainType":%q,"onchainPublicKey":"ocr2on_%s_x","offchainPublicKey":"o","configPublicKey":"c"}}`,
		id, chainType, chainType)
}

func ethKeyJSON(address, chainID string, disabled bool) string {
	return fmt.Sprintf(
		`{"id":%q,"type":"keys","attributes":{"address":%q,"evmChainID":%s,"disabled":%t}}`,
		address+"_"+chainID, address, chainID, disabled)
}

func jobJSON(id, jobType string) string {
	return fmt.Sprintf(`{"id":%q,"type":"jobs","attributes":{"type":%q}}`, id, jobType)
}

// encryptOCR2Export builds a `chainlink keys ocr2 export`-shaped file for priv under password,
// from the same primitives the node writes them with: geth's V3 encryption, the "ocr2key"
// password prefix, and the bundle's JSON layering. It is called from handlers, so a failure
// panics rather than using require: net/http turns that into a broken response the test sees.
func encryptOCR2Export(priv *ecdsa.PrivateKey, password string) []byte {
	inner, err := json.Marshal(struct {
		ChainType string `json:"ChainType"`
		Keyring   []byte `json:"Keyring"`
	}{ChainType: "evm", Keyring: gethcrypto.FromECDSA(priv)})
	if err != nil {
		panic(err)
	}
	cryptoJSON, err := gethkeystore.EncryptDataV3(
		inner, []byte("ocr2key"+password), keystore.FastScryptParams.N, keystore.FastScryptParams.P)
	if err != nil {
		panic(err)
	}
	out, err := json.Marshal(struct {
		ChainType        string                  `json:"chainType"`
		OnchainPublicKey string                  `json:"onchainPublicKey"`
		Crypto           gethkeystore.CryptoJSON `json:"crypto"`
	}{
		ChainType:        "evm",
		OnchainPublicKey: hex.EncodeToString(gethcrypto.PubkeyToAddress(priv.PublicKey).Bytes()),
		Crypto:           cryptoJSON,
	})
	if err != nil {
		panic(err)
	}
	return out
}

// encryptETHExport builds a `chainlink keys eth export`-shaped file for priv under password.
// Called from handlers; see encryptOCR2Export for why failures panic.
func encryptETHExport(priv *ecdsa.PrivateKey, password string) []byte {
	address := gethcrypto.PubkeyToAddress(priv.PublicKey)
	id, err := uuid.FromBytes(address.Bytes()[:16])
	if err != nil {
		panic(err)
	}
	data, err := gethkeystore.EncryptKey(
		&gethkeystore.Key{Id: id, Address: address, PrivateKey: priv},
		password, keystore.FastScryptParams.N, keystore.FastScryptParams.P)
	if err != nil {
		panic(err)
	}
	return data
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	return priv
}

func addressOf(priv *ecdsa.PrivateKey) string {
	return gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()
}

func oneVerifierOneExecutorJSON() string {
	return strings.Join([]string{
		jobJSON("1", JobTypeVerifier),
		jobJSON("2", JobTypeExecutor),
	}, ",")
}
