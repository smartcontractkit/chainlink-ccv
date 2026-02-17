package services

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

const (
	DefaultBootstrapDBName        = "bootstrap_db"
	DefaultBootstrapListenPort    = 9988
	DefaultBootstrapListenPortTCP = "9988/tcp"
)

var (
	CreateBootstrapDBInitScript = fmt.Sprintf(`CREATE DATABASE "%s";`, DefaultBootstrapDBName)
)

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

func GetBootstrapCSAKey(bootstrapURL string) (csaKey string, err error) {
	request := keystore.GetKeysRequest{
		KeyNames: []string{bootstrap.DefaultCSAKeyName},
	}
	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	b := bytes.NewBuffer(jsonRequest)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", bootstrapURL, bootstrap.GetKeysEndpoint), b)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get keys: status code %d", resp.StatusCode)
	}

	var response keystore.GetKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	if len(response.Keys) == 0 {
		return "", fmt.Errorf("no keys returned by bootstrap server")
	}
	if len(response.Keys) != 1 {
		return "", fmt.Errorf("expected 1 key, got %d", len(response.Keys))
	}

	return hex.EncodeToString(response.Keys[0].KeyInfo.PublicKey), nil
}
