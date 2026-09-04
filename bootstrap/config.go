package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
)

// JDConfig is the configuration for the Job Distributor.
type JDConfig struct {
	// ServerWSRPCURL is the URL of the Job Distributor server's WebSocket RPC endpoint.
	ServerWSRPCURL string `toml:"server_wsrpc_url"`
	// ServerCSAPublicKey is the public key of the Job Distributor server's CSA key.
	ServerCSAPublicKey string `toml:"server_csa_public_key"`
}

func (c *JDConfig) validate() error {
	if c.ServerWSRPCURL == "" {
		return fmt.Errorf("ServerWSRPCURL is required")
	}
	if c.ServerCSAPublicKey == "" {
		return fmt.Errorf("ServerCSAPublicKey is required")
	}
	if _, err := keys.DecodeEd25519PublicKey(c.ServerCSAPublicKey); err != nil {
		return fmt.Errorf("invalid ServerCSAPublicKey: %w", err)
	}
	return nil
}

// KeystoreBackend selects the keystore storage backend.
type KeystoreBackend string

const (
	// KeystoreBackendPostgres stores encrypted keys in the bootstrap Postgres database.
	// This is the default when Backend is empty (backward compatibility).
	KeystoreBackendPostgres KeystoreBackend = "postgres"
	// KeystoreBackendKMS stores keys in a cloud KMS (AWS or GCP); private key material never leaves
	// KMS. The provider is selected by [keystore.kms].provider.
	KeystoreBackendKMS KeystoreBackend = "kms"
)

// KMSProvider selects the cloud KMS provider behind the "kms" backend.
type KMSProvider string

const (
	// KMSProviderAWS is AWS Key Management Service.
	KMSProviderAWS KMSProvider = "aws"
	// KMSProviderGCP is Google Cloud Key Management Service.
	KMSProviderGCP KMSProvider = "gcp"
)

// KMSKeystoreConfig configures the cloud KMS keystore backend ("kms"). A single struct carries the
// provider selector and the union of provider-specific fields; only the fields relevant to the
// selected provider are used.
type KMSKeystoreConfig struct {
	// Provider selects the cloud KMS provider: "aws" or "gcp". Required when backend is "kms".
	Provider KMSProvider `toml:"provider,omitempty"`
	// Profile is the AWS shared-config profile name. AWS only. Local development — leave empty in
	// production, where credentials come from the default credential chain (IRSA, EC2/ECS roles).
	Profile string `toml:"profile,omitempty"`
	// Region is the AWS region. AWS only. If empty, it is read from the profile or environment.
	Region string `toml:"region,omitempty"`
	// CredentialsFile is the path to a GCP service account JSON key. GCP only. Local development —
	// leave empty in production, where credentials come from Application Default Credentials (GKE
	// Workload Identity, GCE instance/service accounts, or GOOGLE_APPLICATION_CREDENTIALS).
	CredentialsFile string `toml:"credentials_file,omitempty"`
	// EcdsaKeyID is the KMS key for ECDSA_S256 (secp256k1) signing keys. AWS: a Key ID or ARN.
	// GCP: a CryptoKeyVersion resource name (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>).
	EcdsaKeyID string `toml:"ecdsa_key_id,omitempty"`
	// Ed25519KeyID is the KMS key for Ed25519 keys (e.g. the CSA key for JD auth), same format as
	// EcdsaKeyID. Required in JD mode, where the CSA key authenticates the node to JD. Optional in
	// local mode, where the CSA key only backs Beholder auth: set it to enable that, omit it to run
	// with no Ed25519 key at all.
	Ed25519KeyID string `toml:"ed25519_key_id,omitempty"`
}

// resolveProvider returns the KMS provider. It must be explicitly configured — there is no
// default, so an empty or unknown value is an error rather than a silent fallback to one cloud.
func (c *KMSKeystoreConfig) resolveProvider() (KMSProvider, error) {
	switch c.Provider {
	case KMSProviderAWS, KMSProviderGCP:
		return c.Provider, nil
	default:
		return "", fmt.Errorf("field 'provider' is required and must be %q or %q when backend is 'kms' (got %q)", KMSProviderAWS, KMSProviderGCP, c.Provider)
	}
}

func (c *KMSKeystoreConfig) validateProvider() error {
	_, err := c.resolveProvider()
	return err
}

// KeystoreConfig is the configuration for the keystore.
type KeystoreConfig struct {
	// Backend selects the keystore storage backend: "postgres" (default) or "kms".
	Backend KeystoreBackend `toml:"backend,omitempty"`
	// Password is the password to the keystore. Required when backend is "postgres" (default).
	Password string `toml:"password,omitempty"`
	// KMS configures the cloud KMS backend. Required when backend is "kms".
	//
	// Provider selection: [keystore.kms].provider = "aws" or "gcp" (required). Scope the workload's
	// credentials as tightly as possible to exactly the keys configured below (ecdsa_key_id /
	// ed25519_key_id):
	//
	//   - AWS: grant only kms:Sign, kms:GetPublicKey, and kms:DescribeKey, restricted to exactly the
	//     key ARNs. Do NOT grant kms:ListKeys or a wildcard Resource ("*").
	//   - GCP: grant roles/cloudkms.signerVerifier (or granular cloudkms.cryptoKeyVersions.useToSign,
	//     cloudkms.cryptoKeyVersions.viewPublicKey, cloudkms.cryptoKeys.get) restricted to exactly the
	//     CryptoKeys.
	//
	// The service limits operations to the configured keys, but a per-key least-privilege IAM
	// binding is the primary safeguard: it guarantees these credentials cannot read or sign with any
	// other KMS key the account/role can reach.
	KMS KMSKeystoreConfig `toml:"kms,omitempty"`
}

// validKeystoreBackends is the set of accepted [keystore].backend values. An empty value is not
// listed here — it resolves to the postgres default in resolveBackend for backward compatibility.
var validKeystoreBackends = map[KeystoreBackend]struct{}{
	KeystoreBackendPostgres: {},
	KeystoreBackendKMS:      {},
}

// resolveBackend returns the resolved keystore backend, defaulting to postgres when empty.
func (c *KeystoreConfig) resolveBackend() (KeystoreBackend, error) {
	if c.Backend == "" {
		return KeystoreBackendPostgres, nil
	}
	if _, ok := validKeystoreBackends[c.Backend]; !ok {
		return "", fmt.Errorf("invalid keystore backend %q: must be %q or %q",
			c.Backend, KeystoreBackendPostgres, KeystoreBackendKMS)
	}
	return c.Backend, nil
}

// validate checks the keystore config for the given app-config mode. The Ed25519 requirement is
// mode-driven, not backend-driven: a CSA key (Ed25519) is mandatory only in JD mode, where it
// authenticates the node to JD. In local mode the CSA key is optional (it only backs Beholder
// auth), so no KMS key ID is required here — every key the service declares must still have one,
// enforced per-declared-key in buildKMSNameMap at startup.
func (c *KeystoreConfig) validate(mode AppConfigMode) error {
	backend, err := c.resolveBackend()
	if err != nil {
		return err
	}
	if backend == KeystoreBackendKMS {
		if err := c.KMS.validateProvider(); err != nil {
			return err
		}
		if mode == AppConfigModeJD && c.KMS.Ed25519KeyID == "" {
			return fmt.Errorf("field 'ed25519_key_id' is required when backend is 'kms' in %q mode (the JD CSA key is Ed25519)", AppConfigModeJD)
		}
		return nil
	}
	// postgres
	if c.Password == "" {
		return fmt.Errorf("field 'password' is required when backend is 'postgres' (default)")
	}
	return nil
}

// DBConfig is the configuration for the bootstrap database.
type DBConfig struct {
	// URL is the URL to use for saving jobs and the keystore.
	URL string `toml:"url"`
}

func (c *DBConfig) validate() error {
	if c.URL == "" {
		return fmt.Errorf("field 'url' is required")
	}
	return nil
}

// ServerConfig is the configuration for the HTTP info server.
type ServerConfig struct {
	// ListenPort is the port the HTTP server listens on.
	ListenPort int `toml:"listen_port"`
}

func (c *ServerConfig) validate() error {
	if c.ListenPort == 0 {
		return fmt.Errorf("field 'listen_port' is required")
	}
	return nil
}

// ChainRegistration declares a chain for which the node has a signing identity.
// The bootstrapper uses these entries to publish the node's signing key to JD on connect.
type ChainRegistration struct {
	// Type is the chain family, e.g. "EVM", "SOLANA". Case-insensitive.
	Type string `toml:"type"`
	// ID is the chain identifier, e.g. "1" for Ethereum mainnet.
	ID string `toml:"id"`
}

// KeyImport declares a Chainlink node key to adopt into the keystore instead of generating a fresh
// one. It exists for node operators moving from CL mode to standalone. The import runs only when
// the key is absent, which makes it a no-op on every restart after the first: once the node has
// come up, the exported file and the password file can be unmounted.
//
// It carries two paths and a check, and nothing else. Which keystore key the file becomes
// is not asked: an application declares exactly one key it can import into (a verifier its signing
// key, an executor its transmitter key), so there is nothing for an operator to choose or mistype.
// The export format is read from the file for the same reason.
type KeyImport struct {
	// Path is the mounted path of the key file exported from the Chainlink node.
	Path string `toml:"path"`
	// PasswordPath is the mounted path of a file holding the password used at export time.
	PasswordPath string `toml:"password_path"`
	// ExpectedID pins the address the export must carry. It is required because it is the check
	// that fails the boot when the wrong node's export is mounted — without it the process comes
	// up signing as somebody else, which the committee rejects with nothing pointing at the cause.
	ExpectedID string `toml:"expected_id"`
}

// ToKeysImport converts the config entry to the form the keys package consumes. Format is left
// empty so the keys package detects it from the file.
func (k KeyImport) ToKeysImport() keys.Import {
	return keys.Import{
		Path:         k.Path,
		PasswordPath: k.PasswordPath,
		ExpectedID:   k.ExpectedID,
	}
}

func validateKeyImport(imp *KeyImport) []error {
	if imp == nil {
		return nil
	}
	if err := imp.ToKeysImport().Validate(); err != nil {
		return []error{fmt.Errorf("invalid 'key_import' section: %w", err)}
	}
	return nil
}

// knownChainTypes is the set of chain type strings (upper-cased) for which signing address
// derivation is implemented. Extend this together with signingAddressFromPublicKey in bootstrap.go.
var knownChainTypes = map[string]struct{}{
	"EVM": {}, "SOLANA": {}, "APTOS": {}, "STELLAR": {}, "CANTON": {},
}

func (c ChainRegistration) validate() error {
	if c.Type == "" {
		return fmt.Errorf("field 'type' is required")
	}
	if c.ID == "" {
		return fmt.Errorf("field 'id' is required")
	}
	if _, ok := knownChainTypes[strings.ToUpper(c.Type)]; !ok {
		return fmt.Errorf("unknown chain type %q: must be one of EVM, SOLANA, APTOS", c.Type)
	}
	return nil
}

// NonSecretConfig is the non-secret half of the bootstrap config: the sections that carry no
// credentials. It is embedded into Config, so its sections ([jd], [server], [[chains]],
// [Monitoring]) decode and encode at the top level exactly as if declared on Config directly.
// devenv marshals this type on its own to produce the non-secret config file.
//
// Example non-secret config file (config.toml):
/*
	[jd]
	server_wsrpc_url = "ws://localhost:8080/ws"
	server_csa_public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	[server]
	listen_port = 9988

	[[chains]]
	type = "EVM"
	id = "1"
*/
type NonSecretConfig struct {
	// AppConfigMode selects how the bootstrapper loads application config: "jd_app_config" (default
	// when empty, for backward compatibility) or "local_app_config". See AppConfigMode.
	AppConfigMode AppConfigMode `toml:"app_config_mode,omitempty"`
	// LocalAppConfigPath is the path to the application config file read in local mode. Required when
	// AppConfigMode is "local_app_config"; ignored otherwise. Distinct from the bootstrap config path
	// (BOOTSTRAPPER_CONFIG_PATH): this file holds the app's own config, not the operator/infra config.
	LocalAppConfigPath string `toml:"local_app_config_path,omitempty"`

	JD     JDConfig     `toml:"jd,omitempty"`
	Server ServerConfig `toml:"server,omitempty"`
	// Chains declares the chains on which this node has a signing identity.
	// Each entry causes the bootstrapper to register the node's signing key for that chain in JD.
	// Optional: if empty, no signing key sync is performed.
	Chains []ChainRegistration `toml:"chains"`

	// KeyImport adopts a Chainlink node key into the keystore on first boot instead of generating
	// one. Optional: when absent every declared key is generated, which is right for a new
	// deployment. It is set when migrating an operator off CL mode. When the section is present,
	// expected_id is required.
	KeyImport *KeyImport `toml:"key_import"`

	// Monitoring is the operator-provided monitoring configuration.
	// These are operator- and environment-specific (the OTel exporter endpoints point
	// at a collector deployed alongside the app, typically a k8s sidecar), so they belong in the
	// operator-provided bootstrap config rather than the JD-shipped app config.
	//
	// It is a pointer to distinguish "operator did not configure monitoring here" (nil) from "operator
	// explicitly configured it, possibly with Enabled=false" (non-nil). The apps that consume it (commit
	// verifier, executor) read only this value; their deprecated app-config Monitoring sections are
	// ignored (retained so older job specs still decode). The token verifier is the exception: it loads
	// no bootstrap config and keeps monitoring in its (already operator-provided) mounted app config.
	Monitoring *monitoring.Config `toml:"Monitoring"`
}

// Secrets is the secret half of the bootstrap config: the credential-bearing sections. It is
// embedded into Config, so its sections ([keystore], [db]) decode and encode at the top level
// exactly as if declared on Config directly. devenv marshals this type on its own to produce the
// bootstrap secrets file loaded via BOOTSTRAPPER_SECRETS_PATH.
//
// Example secrets file (secrets.toml) — Postgres backend (default):
/*
	[keystore]
	password = "password"

	[db]
	url = "postgres://localhost:5432/bootstrapper"
*/
//
// Example secrets file (secrets.toml) — KMS backend:
/*
	[keystore]
	backend = "kms"

	[keystore.kms]
	profile = "my-aws-profile"
	region = "us-east-1"
	ecdsa_key_id = "arn:aws:kms:us-east-1:...:key/abc123-..."
	# Required in JD mode (the JD CSA key is Ed25519); optional in local mode.
	ed25519_key_id = "arn:aws:kms:us-east-1:...:key/def456-..."

	[db]
	url = "postgres://localhost:5432/bootstrapper"
*/
type Secrets struct {
	Keystore KeystoreConfig `toml:"keystore,omitempty"`
	DB       DBConfig       `toml:"db,omitempty"`
}

// Config is the full bootstrap config, composed of its non-secret and secret halves. The two halves
// are embedded (not nested) so that a legacy monolithic file — carrying all sections at the top
// level in one file — decodes unchanged, while the split layout decodes the same sections from two
// files. The partition is the single source of truth for which section belongs in which file:
// devenv marshals NonSecretConfig and Secrets independently, and the loader overlays them.
type Config struct {
	NonSecretConfig
	Secrets
}

// validateInfra validates the coupled infra bundle required in JD mode (jd/db/keystore/server/chains).
func (c *Config) validateInfra() []error {
	var errs []error
	if err := c.JD.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'jd' section: %w", err))
	}
	if err := c.Keystore.validate(AppConfigModeJD); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'keystore' section: %w", err))
	}
	if err := c.DB.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'db' section: %w", err))
	}
	if err := c.Server.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'server' section: %w", err))
	}
	errs = append(errs, validateChains(c.Chains)...)
	return errs
}

// validateChains validates each chain entry and enforces that every entry declares the
// same chain family. A committee verifier binary is built for exactly one chain family
// (e.g. EVM XOR Solana, never both) and pushes one signing key for every declared chain
// under the assumption that they're all the same family; mixing families here would
// silently push a key formatted for the wrong chain type to JD, breaking signing key
// sync for whichever family lost the race — this catches that misconfiguration at load
// time instead.
func validateChains(chains []ChainRegistration) []error {
	var errs []error
	var firstType string
	var firstIndex int
	for i, chain := range chains {
		if err := chain.validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid chain at index %d: %w", i, err))
			continue
		}
		upperType := strings.ToUpper(chain.Type)
		if firstType == "" {
			firstType, firstIndex = upperType, i
		} else if upperType != firstType {
			errs = append(errs, fmt.Errorf(
				"chain at index %d has type %q but chains must all declare the same family (found %q at index %d): "+
					"a bootstrapper is built for exactly one chain family and pushes one signing key for all declared chains",
				i, chain.Type, firstType, firstIndex,
			))
		}
	}
	return errs
}

// validate checks the config for correctness. Validation is mode-driven — keyed on the config's
// app_config_mode rather than inferred from which sections happen to be present in the file:
//
//   - AppConfigModeJD: the full infra bundle (jd/db/keystore/server/chains) is required; a missing
//     or invalid section is an error naming that section. This lets a JD-mode app with a malformed
//     bootstrap file fail at load time with a precise message, instead of a downstream connection
//     failure that a present-driven check would allow through.
//   - AppConfigModeLocal: the infra bundle is not required (only services that sign supply
//     [db]+[keystore], and the keystore is initialized only when both are present), but
//     local_app_config_path must be set — that is where the app config is read from.
//
// Monitoring is always validated when non-nil, in every mode.
func (c *Config) validate(m AppConfigMode) error {
	var errs []error
	switch m {
	case AppConfigModeJD:
		errs = append(errs, c.validateInfra()...)
	case AppConfigModeLocal:
		if strings.TrimSpace(c.LocalAppConfigPath) == "" {
			errs = append(errs, fmt.Errorf("field 'local_app_config_path' is required when app_config_mode is %q", AppConfigModeLocal))
		}
		// The infra bundle is optional in local mode, but when a backend is explicitly selected,
		// resolve it so a typo fails at load time rather than at startup. Presence-driven rules
		// (which key IDs, db/password pairing) stay startup-time concerns.
		if c.Keystore.Backend != "" {
			if _, err := c.Keystore.resolveBackend(); err != nil {
				errs = append(errs, fmt.Errorf("failed to validate 'keystore' section: %w", err))
			}
		}
	}
	if c.Monitoring != nil {
		if err := c.Monitoring.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate 'monitoring' section: %w", err))
		}
	}
	// The key import populates the keystore, which both modes initialize when [db] and [keystore]
	// are present, so it is validated in every mode rather than only alongside the JD infra bundle.
	errs = append(errs, validateKeyImport(c.KeyImport)...)
	return errors.Join(errs...)
}

// resolveAppConfigMode returns the config's app_config_mode, defaulting to AppConfigModeJD when
// unset (backward compatibility for existing JD deployments), and errors on an unknown value.
func (c *Config) resolveAppConfigMode() (AppConfigMode, error) {
	switch c.AppConfigMode {
	case "":
		return AppConfigModeJD, nil
	case AppConfigModeJD, AppConfigModeLocal:
		return c.AppConfigMode, nil
	default:
		return "", fmt.Errorf("invalid app_config_mode %q: must be %q or %q", c.AppConfigMode, AppConfigModeJD, AppConfigModeLocal)
	}
}

// LoadAndValidateConfig loads the configuration from one or more TOML files, resolves the
// app_config_mode, validates the merged result for that mode, and returns the resolved mode. Files
// are decoded into cfg in order, and a later file overlays only the sections it defines — so when
// both a non-secret config file and a secrets file are provided, the secrets file wins for any
// section it declares. Because validation runs on the merged struct, "is [db] present and valid" is
// independent of which file supplied it.
func LoadAndValidateConfig(paths []string, cfg *Config) (AppConfigMode, error) {
	for _, path := range paths {
		tomlBytes, err := os.ReadFile(path) //nolint:gosec // G304: path is provided by trusted caller
		if err != nil {
			return "", fmt.Errorf("failed to read config file %q: %w", path, err)
		}
		if err := parseTOML(string(tomlBytes), cfg, true); err != nil {
			return "", fmt.Errorf("failed to parse config %q: %w", path, err)
		}
	}

	mode, err := cfg.resolveAppConfigMode()
	if err != nil {
		return "", err
	}
	if err := cfg.validate(mode); err != nil {
		return "", fmt.Errorf("config validation failed: %w", err)
	}
	return mode, nil
}

func parseTOML[T any](tomlString string, out *T, strict bool) error {
	md, err := toml.Decode(tomlString, out)
	if err != nil {
		return fmt.Errorf("failed to decode toml: %w", err)
	}
	if strict && len(md.Undecoded()) > 0 {
		return fmt.Errorf("strict decode failed, found undecoded fields: %+v", md.Undecoded())
	}
	return nil
}
