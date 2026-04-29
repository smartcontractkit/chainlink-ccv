package services

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	bskeys "github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

const (
	DefaultBootstrapDBName        = "bootstrap_db"
	DefaultBootstrapListenPort    = 9988
	DefaultBootstrapListenPortTCP = "9988/tcp"
)

var CreateBootstrapDBInitScript = fmt.Sprintf(`CREATE DATABASE "%s";`, DefaultBootstrapDBName)

// BootstrapInput describes the input to the app bootstrapper.
type BootstrapInput struct {
	Keystore *bootstrap.KeystoreConfig `toml:"keystore"`
	Server   *bootstrap.ServerConfig   `toml:"server"`
	// These fields can't be specified in the env.toml without actually spinning up the environment.
	// They get populated while the environment is being spun up.
	DB *bootstrap.DBConfig `toml:"-"`
	JD *bootstrap.JDConfig `toml:"-"`
}

func ApplyBootstrapDefaults(in BootstrapInput) BootstrapInput {
	if in.Keystore == nil {
		in.Keystore = &bootstrap.KeystoreConfig{
			Password: "devenv-password",
		}
	}
	if in.Server == nil {
		in.Server = &bootstrap.ServerConfig{
			ListenPort: 9988,
		}
	}
	// Ensure these are non-nil, will be filled in by the environment.
	if in.DB == nil {
		in.DB = &bootstrap.DBConfig{}
	}
	if in.JD == nil {
		in.JD = &bootstrap.JDConfig{}
	}
	return in
}

func CreateBootstrapDBInitScriptFile() (path string, err error) {
	tempFile, err := os.CreateTemp(os.TempDir(), "bootstrap-db-init-script-*.sql")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		err = tempFile.Sync()
		if err != nil {
			return
		}
		err = tempFile.Close()
		if err != nil {
			return
		}
	}()

	_, err = tempFile.WriteString(CreateBootstrapDBInitScript)
	if err != nil {
		return "", fmt.Errorf("failed to write init script to file: %w", err)
	}
	return tempFile.Name(), nil
}

// GenerateBootstrapConfig marshals the bootstrap configuration to TOML.
func GenerateBootstrapConfig(in BootstrapInput) ([]byte, error) {
	config := bootstrap.Config{
		Keystore: *in.Keystore,
		DB:       *in.DB,
		JD:       *in.JD,
		Server:   *in.Server,
	}
	return toml.Marshal(config)
}

// BootstrapKeys are the keys that are ensured to exist by the bootstrap library,
// in hexadecimal format.
type BootstrapKeys struct {
	// CSAPublicKey is the CSA public key used for JD communcations.
	CSAPublicKey string `toml:"csa_public_key"`
	// ECDSAPublicKey is the public key used to sign messages using ECDSA.
	ECDSAPublicKey string `toml:"ecdsa_public_key"`
	// ECDSAAddress is the Ethereum address derived from the ECDSA public key.
	ECDSAAddress string `toml:"ecdsa_address"`
}

// GetExecutorBootstrapKeys fetches only the CSA key from the bootstrap server.
// Executors only need the CSA key for JD registration.
func GetExecutorBootstrapKeys(bootstrapURL string) (BootstrapKeys, error) {
	return fetchBootstrapKeys(bootstrapURL, []string{bskeys.DefaultCSAKeyName}, false)
}

// GetBootstrapKeys fetches the CSA and ECDSA keys from the bootstrap server.
// Verifiers need both for JD registration and signing.
func GetBootstrapKeys(bootstrapURL string) (BootstrapKeys, error) {
	return fetchBootstrapKeys(bootstrapURL, []string{bskeys.DefaultCSAKeyName, bskeys.DefaultECDSASigningKeyName}, true)
}

func fetchBootstrapKeys(bootstrapURL string, keyNames []string, includeECDSA bool) (BootstrapKeys, error) {
	request := keystore.GetKeysRequest{KeyNames: keyNames}
	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to marshal request: %w", err)
	}
	b := bytes.NewBuffer(jsonRequest)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", bootstrapURL, bootstrap.GetKeysEndpoint), b)
	if err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to get keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return BootstrapKeys{}, fmt.Errorf("failed to get keys: status code %d", resp.StatusCode)
	}

	var response keystore.GetKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to decode response: %w", err)
	}
	if len(response.Keys) != len(keyNames) {
		return BootstrapKeys{}, fmt.Errorf("expected %d keys, got %d", len(keyNames), len(response.Keys))
	}

	// Build a name→key map; the keystore returns keys sorted alphabetically,
	// not in request order, so positional indexing is unsafe.
	keyMap := make(map[string]keystore.GetKeyResponse, len(response.Keys))
	for _, k := range response.Keys {
		keyMap[k.KeyInfo.Name] = k
	}

	csaKey, ok := keyMap[bskeys.DefaultCSAKeyName]
	if !ok {
		return BootstrapKeys{}, fmt.Errorf("CSA key %q not found in response", bskeys.DefaultCSAKeyName)
	}
	result := BootstrapKeys{
		CSAPublicKey: hex.EncodeToString(csaKey.KeyInfo.PublicKey),
	}

	if includeECDSA {
		ecdsaKeyResp, ok := keyMap[bskeys.DefaultECDSASigningKeyName]
		if !ok {
			return BootstrapKeys{}, fmt.Errorf("ECDSA key %q not found in response", bskeys.DefaultECDSASigningKeyName)
		}
		ecdsaPublicKey, err := crypto.UnmarshalPubkey(ecdsaKeyResp.KeyInfo.PublicKey)
		if err != nil {
			return BootstrapKeys{}, fmt.Errorf("failed to unmarshal ECDSA public key: %w", err)
		}
		result.ECDSAPublicKey = hex.EncodeToString(ecdsaKeyResp.KeyInfo.PublicKey)
		result.ECDSAAddress = hex.EncodeToString(crypto.PubkeyToAddress(*ecdsaPublicKey).Bytes())
	}

	return result, nil
}
