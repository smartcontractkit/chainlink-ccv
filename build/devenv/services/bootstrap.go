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
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
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
	// EdDSAPublicKey is the public key used to sign messages using EdDSA.
	EdDSAPublicKey string `toml:"ed25519_public_key"`
}

// GetBootstrapKeys fetches the keys that are ensured to exist by the bootstrap library.
func GetBootstrapKeys(bootstrapURL string) (keys BootstrapKeys, err error) {
	request := keystore.GetKeysRequest{
		KeyNames: []string{
			keys.DefaultCSAKeyName,
			keys.DefaultECDSASigningKeyName,
			keys.DefaultEdDSASigningKeyName,
		},
	}
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
	if len(response.Keys) == 0 {
		return BootstrapKeys{}, fmt.Errorf("no keys returned by bootstrap server")
	}
	if len(response.Keys) != 3 {
		return BootstrapKeys{}, fmt.Errorf("expected 3 keys, got %d", len(response.Keys))
	}

	// Transform ECDSA public key to Ethereum address.
	ecdsaPublicKey, err := crypto.UnmarshalPubkey(response.Keys[1].KeyInfo.PublicKey)
	if err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to unmarshal ECDSA public key: %w", err)
	}
	ecdsaAddress := crypto.PubkeyToAddress(*ecdsaPublicKey).Bytes()

	return BootstrapKeys{
		CSAPublicKey:   hex.EncodeToString(response.Keys[0].KeyInfo.PublicKey),
		ECDSAPublicKey: hex.EncodeToString(response.Keys[1].KeyInfo.PublicKey),
		ECDSAAddress:   hex.EncodeToString(ecdsaAddress),
		EdDSAPublicKey: hex.EncodeToString(response.Keys[2].KeyInfo.PublicKey),
	}, nil
}
