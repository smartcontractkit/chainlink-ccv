package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

const (
	DefaultBootstrapDBName = "bootstrap_db"
	// DefaultKeystorePassword is the keystore encryption password used for devenv bootstrappers. It must
	// match on both the seed path (SeedBootstrapKeys) and the running container so the container can
	// decrypt the seeded keys.
	DefaultKeystorePassword       = "devenv-password"
	DefaultBootstrapListenPort    = 9988
	DefaultBootstrapListenPortTCP = "9988/tcp"
)

var CreateBootstrapDBInitScript = fmt.Sprintf(`CREATE DATABASE "%s";`, DefaultBootstrapDBName)

// BootstrapInput describes the input to the app bootstrapper.
type BootstrapInput struct {
	Keystore   *bootstrap.KeystoreConfig `toml:"keystore"`
	Server     *bootstrap.ServerConfig   `toml:"server"`
	Monitoring *monitoring.Config        `toml:"monitoring"`
	// AppConfigMode and LocalAppConfigPath select the bootstrapper lifecycle in the generated
	// non-secret config. Left empty they default to JD mode (backward compatible). In local mode,
	// AppConfigMode is "local_app_config" and LocalAppConfigPath is the in-container path of the
	// mounted app-config file. Set at launch, not from env.toml.
	AppConfigMode      bootstrap.AppConfigMode `toml:"-"`
	LocalAppConfigPath string                  `toml:"-"`
	// These fields can't be specified in the env.toml without actually spinning up the environment.
	// They get populated while the environment is being spun up.
	DB *bootstrap.DBConfig `toml:"-"`
	JD *bootstrap.JDConfig `toml:"-"`
	// Chains declares the chains on which this node has a signing identity.
	// Populated at launch time from the blockchain outputs so the bootstrapper
	// syncs the node's signing key to JD on connect.
	Chains []bootstrap.ChainRegistration `toml:"-"`
}

func ApplyBootstrapDefaults(in BootstrapInput) BootstrapInput {
	if in.Keystore == nil {
		in.Keystore = &bootstrap.KeystoreConfig{
			Password: DefaultKeystorePassword,
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

// GenerateBootstrapConfig marshals the non-secret bootstrap config ([jd], [server], [[chains]],
// [Monitoring]) to TOML. Credentials go to a separate secrets file; see GenerateBootstrapSecrets.
// It marshals bootstrap.NonSecretConfig directly so the partition stays defined in one place.
func GenerateBootstrapConfig(in BootstrapInput) ([]byte, error) {
	return toml.Marshal(bootstrap.NonSecretConfig{
		AppConfigMode:      in.AppConfigMode,
		LocalAppConfigPath: in.LocalAppConfigPath,
		JD:                 *in.JD,
		Server:             *in.Server,
		Chains:             in.Chains,
		Monitoring:         in.Monitoring,
	})
}

// GenerateBootstrapSecrets marshals the credential-bearing bootstrap sections ([keystore], [db]) to
// TOML, for the bootstrap secrets file loaded via BOOTSTRAPPER_SECRETS_PATH. It marshals
// bootstrap.Secrets directly so the partition stays defined in one place.
func GenerateBootstrapSecrets(in BootstrapInput) ([]byte, error) {
	return toml.Marshal(bootstrap.Secrets{
		Keystore: *in.Keystore,
		DB:       *in.DB,
	})
}

// BootstrapKeys holds the public keys exposed by the bootstrap info-server.
type BootstrapKeys struct {
	// CSAPublicKey is the CSA public key used for JD communications.
	CSAPublicKey string `toml:"csa_public_key"`
	// ECDSAPublicKey is the ECDSA signing public key (verifier only).
	ECDSAPublicKey string `toml:"ecdsa_public_key,omitempty"`
	// ECDSAAddress is the Ethereum address derived from the ECDSA public key (verifier only).
	ECDSAAddress string `toml:"ecdsa_address,omitempty"`
	// PublicKeys is a map of full keystore key names (like evm/tx/executor_evm_transmitter_key).
	// Values are the corresponding public keys as lowercase hex-encoded raw bytes
	PublicKeys map[string]string `toml:"public_keys,omitempty"`
}

// PublicKeyHex returns the hex-encoded raw public key for keyName, or "" if absent.
func (k BootstrapKeys) PublicKeyHex(keyName string) string {
	if k.PublicKeys == nil {
		return ""
	}
	return k.PublicKeys[keyName]
}

// FetchBootstrapKeys queries the bootstrap HTTP info server for public key material by name.
// Devenv calls this after a container starts to retrieve keys needed for JD registration and on-chain funding.
func FetchBootstrapKeys(bootstrapURL string, keyNames ...string) (BootstrapKeys, error) {
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

	// Build a name→key map; the keystore returns keys sorted alphabetically,
	// not in request order, so positional indexing is unsafe.
	keyMap := make(map[string]keystore.GetKeyResponse, len(response.Keys))
	for _, k := range response.Keys {
		keyMap[k.KeyInfo.Name] = k
	}

	// Confirm every requested name is present — a count match alone doesn't
	// catch the server returning a different key with the same cardinality.
	for _, name := range keyNames {
		if _, ok := keyMap[name]; !ok {
			return BootstrapKeys{}, fmt.Errorf("key %q not found in response", name)
		}
	}

	keyInfos := make(map[string]keystore.KeyInfo, len(keyMap))
	for name, resp := range keyMap {
		keyInfos[name] = resp.KeyInfo
	}
	return buildBootstrapKeys(keyInfos, keyNames)
}

// SeedBootstrapKeys generates the given keys directly in a bootstrapper's Postgres keystore (without
// running the service) and returns their public material as BootstrapKeys, mirroring what
// FetchBootstrapKeys returns once a container is up. The local (no-JD) devenv path uses it to learn a
// node's signer address before the container starts, so the on-chain config and app config can be
// built up front. dbURL is the host-reachable keystore connection string, ksPassword the keystore
// password; the running container later finds these same keys already present.
func SeedBootstrapKeys(ctx context.Context, dbURL, ksPassword string, specs []KeySpec) (BootstrapKeys, error) {
	seeded, err := seedKeys(ctx, dbURL, ksPassword, specs)
	if err != nil {
		return BootstrapKeys{}, fmt.Errorf("failed to seed bootstrap keys: %w", err)
	}
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.Name)
	}
	return buildBootstrapKeys(seeded, names)
}

// buildBootstrapKeys assembles a BootstrapKeys from a name->KeyInfo map, shared by the HTTP fetch and
// the local seed paths. The CSA and ECDSA signing keys map to dedicated fields (the ECDSA public key
// is also reduced to its EVM address); any other requested key goes into PublicKeys by name.
func buildBootstrapKeys(keyInfos map[string]keystore.KeyInfo, keyNames []string) (BootstrapKeys, error) {
	var result BootstrapKeys
	if csa, ok := keyInfos[bootstrap.DefaultCSAKeyName]; ok {
		result.CSAPublicKey = hex.EncodeToString(csa.PublicKey)
	}

	if ecdsa, ok := keyInfos[commit.DefaultECDSASigningKeyName]; ok {
		ecdsaPublicKey, err := crypto.UnmarshalPubkey(ecdsa.PublicKey)
		if err != nil {
			return BootstrapKeys{}, fmt.Errorf("failed to unmarshal ECDSA public key: %w", err)
		}
		result.ECDSAPublicKey = hex.EncodeToString(ecdsa.PublicKey)
		result.ECDSAAddress = hex.EncodeToString(crypto.PubkeyToAddress(*ecdsaPublicKey).Bytes())
	}

	for _, name := range keyNames {
		if name == bootstrap.DefaultCSAKeyName || name == commit.DefaultECDSASigningKeyName {
			continue
		}
		info, ok := keyInfos[name]
		if !ok {
			continue
		}
		if result.PublicKeys == nil {
			result.PublicKeys = make(map[string]string)
		}
		result.PublicKeys[name] = hex.EncodeToString(info.PublicKey)
	}

	return result, nil
}
