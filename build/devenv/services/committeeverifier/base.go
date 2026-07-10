package committeeverifier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/keystore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	DefaultVerifierName    = "verifier"
	DefaultVerifierDBName  = "verifier-db"
	DefaultVerifierImage   = "verifier:latest"
	DefaultVerifierPort    = 8100
	DefaultVerifierPortTCP = "8100/tcp"
	DefaultVerifierDBPort  = 8432
	DefaultVerifierMode    = services.Standalone

	DefaultVerifierDBImage = "postgres:16-alpine"

	// localAppConfigContainerPath is where the local-mode app config lives inside the container (written
	// into the bootstrap config as local_app_config_path). It is copied into the container image at
	// creation time (testcontainers Files), so it is present before the bootstrapper starts.
	localAppConfigContainerPath = "/etc/committee-verifier-app.toml"
)

var DefaultVerifierDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultVerifierName, DefaultVerifierName, DefaultVerifierDBPort, DefaultVerifierName)

// ReqModifier modifies a committee verifier testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	verifierInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)

type DBInput struct {
	Image string `toml:"image"`
	Name  string `toml:"name"`
	Port  int    `toml:"port"`
}

type EnvConfig struct {
	AggregatorAPIKey    string `toml:"aggregator_api_key"`
	AggregatorSecretKey string `toml:"aggregator_secret_key"`
}

type Input struct {
	Mode           services.Mode `toml:"mode"`
	DB             *DBInput      `toml:"db"`
	Out            *Output       `toml:"out"`
	Image          string        `toml:"image"`
	SourceCodePath string        `toml:"source_code_path"`
	RootPath       string        `toml:"root_path"`
	ContainerName  string        `toml:"container_name"`
	NOPAlias       string        `toml:"nop_alias"`
	Port           int           `toml:"port"`
	UseCache       bool          `toml:"use_cache"`
	Env            *EnvConfig    `toml:"env"`
	CommitteeName  string        `toml:"committee_name"`
	NodeIndex      int           `toml:"node_index"`
	// ChainFamily is the chain family that we should launch a verifier for.
	// Defaults to just "evm" if not specified.
	ChainFamily string `toml:"chain_family"`

	// Bootstrap is the map of chain families to bootstrap configurations.
	// Defaults to just {"evm": {}} if not specified.
	Bootstrap *services.BootstrapInput `toml:"bootstrap"`

	// OpaqueConfigs is a map of chain family name to opaque configuration to pass onto the verifier,
	// only used in standalone mode.
	OpaqueConfigs map[string]util.OpaqueConfig `toml:"opaque_configs"`

	// DisableFinalityCheckers is a list of chain selectors for which the finality violation checker should be disabled.
	// The chain selectors are formatted as strings of the chain selector.
	DisableFinalityCheckers []string `toml:"disable_finality_checkers"`

	// TLSCACertFile is the path to the CA certificate file for TLS verification.
	TLSCACertFile string `toml:"-"`

	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`

	// AggregatorOutput is optionally set to automatically obtain credentials.
	AggregatorOutput *services.AggregatorOutput `toml:"-"`

	// AggregatorCredentials maps each aggregator's SecretName -> this verifier's HMAC credentials
	// at that aggregator. In the consolidated topology the verifier writes to every aggregator,
	// each with its own credential; the launch code populates this from each aggregator's output.
	// Keyed by SecretName so base.go can emit VERIFIER_AGGREGATOR_<SECRETNAME>_API_KEY/SECRET_KEY
	// directly, matching what the runtime reads — no dependency on the generated config.
	AggregatorCredentials map[string]hmacutil.Credentials `toml:"-"`

	// GeneratedJobSpecs contains all job specs for this verifier, one per aggregator in the committee.
	GeneratedJobSpecs []bootstrap.JobSpec `toml:"-"`

	// GeneratedConfig is the verifier configuration TOML derived from
	// GeneratedJobSpecs[NodeIndex % numAggregators].
	// Used in standalone mode. Set by generateVerifierJobSpecs in environment.go.
	GeneratedConfig string `toml:"-"`

	// LocalAppConfig is the plain app-config TOML mounted into the container in local mode
	// (services.Local) — the committee verifier's commit.Config with blockchain_infos included, the
	// same content JD would ship in a job's appConfig, no envelope. Callers build it (base.go cannot
	// build it itself because that needs the chainreg registry, which imports this package). When set,
	// it is copied into the container at creation, so the bootstrapper reads a config present at boot.
	//
	// This single-shot field is for callers that already know the config up front (e.g. tests). The
	// no-JD devenv environment does not use it: there the config depends on contract addresses that are
	// not known until after the container's signer address is registered on-chain, so it uses the
	// two-phase PrepareLocal (seed key) / LaunchLocalWithConfig (start with config) flow instead.
	LocalAppConfig string `toml:"-"`
}

// configWithBlockchainInfos is the committee verifier's app config plus the blockchain_infos section
// (RPC URLs etc.). Standalone/local verifiers need blockchain_infos inlined because, unlike CL-mode
// verifiers, they have no CL node to source chain connection info from.
type configWithBlockchainInfos struct {
	commit.Config
	BlockchainInfos map[string]any `toml:"blockchain_infos"`
}

// BuildVerifierAppConfigWithBlockchainInfos parses the verifier config out of a job spec and
// re-marshals it with blockchain_infos included, returning the plain app-config TOML — the exact
// content JD ships as a job's appConfig, with no job-spec envelope. This is what a local-mode
// bootstrapper reads from its mounted config file.
func BuildVerifierAppConfigWithBlockchainInfos(spec bootstrap.JobSpec, blockchainInfos map[string]any) (string, error) {
	var cfg commit.Config
	if err := spec.GetAppConfig(&cfg); err != nil {
		return "", fmt.Errorf("failed to parse verifier config from job spec: %w", err)
	}
	innerConfigBytes, err := toml.Marshal(configWithBlockchainInfos{Config: cfg, BlockchainInfos: blockchainInfos})
	if err != nil {
		return "", fmt.Errorf("failed to marshal enhanced config: %w", err)
	}
	return string(innerConfigBytes), nil
}

// RebuildVerifierJobSpecWithBlockchainInfos takes a job spec and rebuilds it with blockchain infos
// added to the inner config. This is needed for standalone verifiers which require blockchain
// connection information (CL nodes get this from their own chain config).
// TODO: we stick with the job spec so that there isn't special logic for standalone verifiers.
func RebuildVerifierJobSpecWithBlockchainInfos(spec bootstrap.JobSpec, blockchainInfos map[string]any) (string, error) {
	innerConfig, err := BuildVerifierAppConfigWithBlockchainInfos(spec, blockchainInfos)
	if err != nil {
		return "", err
	}

	// Rebuild the job spec with the enhanced config
	spec.AppConfig = innerConfig
	outerSpecBytes, err := toml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal job spec: %w", err)
	}

	return string(outerSpecBytes), nil
}

type Output struct {
	VerifierID         string `toml:"verifier_id"`
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
	UseCache           bool   `toml:"use_cache"`

	// Bootstrap DB outputs
	BootstrapDBURL              string                 `toml:"bootstrap_db_url"`
	BootstrapDBConnectionString string                 `toml:"bootstrap_db_connection_string"`
	BootstrapKeys               services.BootstrapKeys `toml:"bootstrap_keys"`

	// JDNodeID is set after the bootstrap is registered with JD.
	JDNodeID string `toml:"jd_node_id"`

	// Container is the running verifier container, retained in local mode. Not serialized. Nil until the
	// container is started (in the no-JD two-phase path, nil after PrepareLocal and set by
	// LaunchLocalWithConfig).
	Container testcontainers.Container `toml:"-"`

	// dbContainer is the bootstrap Postgres container, created by PrepareLocal before the main container
	// so its keystore can be seeded, and reused by LaunchLocalWithConfig to resolve the mapped DB port.
	// Not serialized. Only set on the no-JD two-phase local path.
	dbContainer testcontainers.Container `toml:"-"`
}

func ApplyDefaults(in Input) Input {
	if in.Image == "" {
		in.Image = DefaultVerifierImage
	}
	if in.Port == 0 {
		in.Port = DefaultVerifierPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultVerifierName
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image: DefaultVerifierDBImage,
			Name:  DefaultVerifierDBName,
			Port:  DefaultVerifierDBPort,
		}
	}
	if in.Mode == "" {
		in.Mode = DefaultVerifierMode
	}
	if in.ChainFamily == "" {
		in.ChainFamily = chainsel.FamilyEVM
	}
	if in.Bootstrap == nil {
		def := services.ApplyBootstrapDefaults(services.BootstrapInput{})
		in.Bootstrap = &def
	} else {
		def := services.ApplyBootstrapDefaults(*in.Bootstrap)
		in.Bootstrap = &def
	}
	return in
}

func New(in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier) (*Output, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	// Local mode runs without a Job Distributor, so jdInfra is not required there.
	if in.Mode != services.Local && jdInfra == nil {
		return nil, fmt.Errorf("JD infrastructure is not set")
	}

	out, err := launchVerifier(ctx, in, outputs, jdInfra, modifiers)
	if err != nil {
		return nil, fmt.Errorf("failed to launch verifier: %w", err)
	}

	return out, nil
}

// generateVerifierConfigFiles writes the bootstrap config, bootstrap secrets, and verifier secrets
// files to the CCV config dir and returns their paths plus the container env vars. It also appends
// this node's signing chains to bootstrapInput.Chains. Shared by the JD and local launch paths.
func generateVerifierConfigFiles(in *Input, outputs []*blockchain.Output, bootstrapInput *services.BootstrapInput) (bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath string, envVars map[string]string, err error) {
	aggregatorSecrets, err := getAggregatorSecretEntries(in)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to get aggregator secrets: %w", err)
	}

	// Database connection for chain status (internal docker network address).
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), in.ContainerName)

	// Deliver the DB URL and per-aggregator HMAC credentials via the verifier secrets file,
	// mounted at the default path, instead of the CL_DATABASE_URL / VERIFIER_AGGREGATOR_* env vars —
	// so e2e exercises the file load path.
	verifierSecrets, err := services.GenerateVerifierSecrets(internalDBConnectionString, aggregatorSecrets)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to generate verifier secrets: %w", err)
	}

	envVars = make(map[string]string)
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		envVars["LOG_LEVEL"] = lvl
	}

	// Register each matching chain family blockchain output as a chain the node has a signing identity on.
	// This causes the bootstrapper to sync the node's signing key to JD on connect,
	// making it available to deployment changesets via ListNodeChainConfigs.
	for _, output := range outputs {
		if output.ChainID != "" && output.Family == in.ChainFamily {
			bootstrapInput.Chains = append(bootstrapInput.Chains, bootstrap.ChainRegistration{
				Type: in.ChainFamily,
				ID:   output.ChainID,
			})
		}
	}

	// Generate and store config file.
	bootstrapConfig, err := services.GenerateBootstrapConfig(*bootstrapInput)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to generate bootstrap config: %w", err)
	}
	bootstrapSecrets, err := services.GenerateBootstrapSecrets(*bootstrapInput)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to generate bootstrap secrets: %w", err)
	}
	confDir := util.CCVConfigDir()
	bootstrapConfigFilePath = filepath.Join(confDir,
		fmt.Sprintf("bootstrap-%s-config-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return "", "", "", nil, fmt.Errorf("failed to write bootstrap config to file: %w", err)
	}
	bootstrapSecretsFilePath = filepath.Join(confDir,
		fmt.Sprintf("bootstrap-%s-secrets-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(bootstrapSecretsFilePath, bootstrapSecrets, 0o644); err != nil {
		return "", "", "", nil, fmt.Errorf("failed to write bootstrap secrets to file: %w", err)
	}
	verifierSecretsFilePath = filepath.Join(confDir,
		fmt.Sprintf("verifier-%s-secrets-%d.toml", in.CommitteeName, in.NodeIndex+1))
	// 0o644 (world-readable) matches the bootstrap secrets file: the mounted file must be readable by
	// the `ccv` CLI run via `docker exec`, which may run as a different UID than the bind-mount owner.
	if err := os.WriteFile(verifierSecretsFilePath, verifierSecrets, 0o644); err != nil {
		return "", "", "", nil, fmt.Errorf("failed to write verifier secrets to file: %w", err)
	}

	return bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, envVars, nil
}

func launchVerifier(ctx context.Context, in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier) (*Output, error) {
	// local mode runs without JD: the app config is delivered via a mounted job-spec file rather than
	// a JD job proposal, so all JD wiring below is skipped.
	local := in.Mode == services.Local

	bootstrapInput := in.Bootstrap
	dbContainer, err := createDBContainer(ctx, in, in.ChainFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier database: %w", err)
	}

	// Update bootstrap config w/ the keystore/ORM database URL (needed in every mode).
	// TODO: make this easier? All standalone setups will have to do the same thing.
	bootstrapInput.DB.URL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), services.DefaultBootstrapDBName)

	if !local {
		// Point the bootstrapper at JD. In local mode [jd] is left blank (omitted by omitempty and
		// not required by the loader's local-mode validation).
		jdCSAKey, err := jobs.GetJDCSAPublicKey(ctx, jdInfra.OffchainClient)
		if err != nil {
			return nil, fmt.Errorf("failed to get JD server CSA public key: %w", err)
		}
		bootstrapInput.JD.ServerCSAPublicKey = jdCSAKey
		bootstrapInput.JD.ServerWSRPCURL = jdInfra.JDOutput.InternalWSRPCUrl
	} else {
		// Local mode: the bootstrap config declares the mode and where to read the app config from.
		bootstrapInput.AppConfigMode = bootstrap.AppConfigModeLocal
		bootstrapInput.LocalAppConfigPath = localAppConfigContainerPath
	}

	bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, envVars, err := generateVerifierConfigFiles(in, outputs, bootstrapInput)
	if err != nil {
		return nil, err
	}

	// In local mode the app config is mounted into the container at local_app_config_path so it is
	// present at startup (in.LocalAppConfig, set by the no-JD path once contracts are deployed). JD mode
	// leaves it empty and receives config via a job proposal.
	req, err := baseImageRequest(in, envVars, bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, in.LocalAppConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base image request: %w", err)
	}

	// Get the modifier for the chain family.
	modifier, ok := modifiers[in.ChainFamily]
	if !ok {
		return nil, fmt.Errorf("no modifier found for chain family %s", in.ChainFamily)
	}

	framework.L.Info().
		Str("Service", in.ContainerName).
		Str("ChainFamily", in.ChainFamily).
		Msg("Using modifier for chain family")

	// Modify the request.
	req, err = modifier(req, in, outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to modify request: %w", err)
	}

	framework.L.Info().
		Str("Service", in.ContainerName).
		Str("ChainFamily", in.ChainFamily).
		Msg("Successfully modified request for chain family")

	c, err := startContainer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Fetch the CSA and ECDSA keys from the bootstrap server. Verifiers need both for JD registration
	// and committee signer registration. (The local two-phase path seeds keys instead — see PrepareLocal.)
	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}
	bootstrapMapped, err := c.MappedPort(ctx, services.DefaultBootstrapListenPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap mapped port: %w", err)
	}
	bootstrapURL := fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port())
	bootstrapKeys, err := services.FetchBootstrapKeys(bootstrapURL, bootstrap.DefaultCSAKeyName, commit.DefaultECDSASigningKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap keys: %w", err)
	}

	out, err := finalizeVerifierOutput(ctx, c, dbContainer, in, bootstrapKeys)
	if err != nil {
		return nil, err
	}
	if local {
		out.Container = c
	}
	return out, nil
}

// finalizeVerifierOutput resolves the running container's mapped ports and builds the verifier Output.
// bootstrapKeys are supplied by the caller (fetched from the info server in JD mode, seeded up front in
// the local two-phase path). Shared by launchVerifier and LaunchLocalWithConfig.
func finalizeVerifierOutput(ctx context.Context, c, dbContainer testcontainers.Container, in *Input, bootstrapKeys services.BootstrapKeys) (*Output, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}
	bootstrapMapped, err := c.MappedPort(ctx, services.DefaultBootstrapListenPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap mapped port: %w", err)
	}
	verifierMapped, err := c.MappedPort(ctx, DefaultVerifierPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier mapped port: %w", err)
	}
	inspect, err := c.Inspect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}
	dbMapped, err := dbContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to get database mapped port: %w", err)
	}

	containerName := strings.TrimPrefix(inspect.Name, "/")
	return &Output{
		ContainerName:   inspect.Name,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%s", host, verifierMapped.Port()),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", containerName, DefaultVerifierPort),
		DBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), in.ContainerName),
		BootstrapDBURL: fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port()),
		BootstrapDBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName),
		BootstrapKeys: bootstrapKeys,
	}, nil
}

// PrepareLocal starts the verifier's bootstrap Postgres and seeds its signing keys, without starting
// the verifier container. It returns an Output whose BootstrapKeys are populated — so the no-JD
// environment can enrich the on-chain committee/signer config before any verifier container runs — and
// whose bootstrap DB container is retained for LaunchLocalWithConfig. The verifier container is started
// later, once the app config is known, by LaunchLocalWithConfig.
func PrepareLocal(ctx context.Context, in *Input, outputs []*blockchain.Output) (*Output, error) {
	if in.Mode != services.Local {
		return nil, fmt.Errorf("PrepareLocal requires local mode, got %q", in.Mode)
	}
	dbContainer, err := createDBContainer(ctx, in, in.ChainFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier database: %w", err)
	}
	dbMapped, err := dbContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to get database mapped port: %w", err)
	}
	// Seed via the host-mapped port; the container itself later reaches the same DB over the docker
	// network alias. Key names/types match the WithKey options in the committee verifier's main, so the
	// container finds these keys already present instead of generating new ones.
	seedDBURL := fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName)
	bootstrapKeys, err := services.SeedBootstrapKeys(ctx, seedDBURL, localKeystorePassword(in), []services.KeySpec{
		{Name: bootstrap.DefaultCSAKeyName, Purpose: "csa", Type: keystore.Ed25519},
		{Name: commit.DefaultECDSASigningKeyName, Purpose: "signing", Type: keystore.ECDSA_S256},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to seed verifier keys: %w", err)
	}
	return &Output{BootstrapKeys: bootstrapKeys, dbContainer: dbContainer}, nil
}

// LaunchLocalWithConfig starts the verifier container prepared by PrepareLocal, with the app config
// mounted so it is present at startup. It reuses the seeded keystore (prepared.BootstrapKeys) and the
// bootstrap DB created by PrepareLocal, so no keys are fetched from the container. appConfigTOML is the
// committee verifier's app config (with blockchain_infos), built after contracts are deployed. On
// success it populates prepared in place with the running container's outputs.
func LaunchLocalWithConfig(ctx context.Context, prepared *Output, in *Input, outputs []*blockchain.Output, modifiers map[string]ReqModifier, appConfigTOML string) error {
	if prepared == nil || prepared.dbContainer == nil {
		return fmt.Errorf("verifier was not prepared for local mode (call PrepareLocal first)")
	}

	bootstrapInput := in.Bootstrap
	bootstrapInput.DB.URL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), services.DefaultBootstrapDBName)
	bootstrapInput.AppConfigMode = bootstrap.AppConfigModeLocal
	bootstrapInput.LocalAppConfigPath = localAppConfigContainerPath

	bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, envVars, err := generateVerifierConfigFiles(in, outputs, bootstrapInput)
	if err != nil {
		return err
	}

	req, err := baseImageRequest(in, envVars, bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, appConfigTOML)
	if err != nil {
		return fmt.Errorf("failed to create base image request: %w", err)
	}

	modifier, ok := modifiers[in.ChainFamily]
	if !ok {
		return fmt.Errorf("no modifier found for chain family %s", in.ChainFamily)
	}
	req, err = modifier(req, in, outputs)
	if err != nil {
		return fmt.Errorf("failed to modify request: %w", err)
	}

	c, err := startContainer(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	out, err := finalizeVerifierOutput(ctx, c, prepared.dbContainer, in, prepared.BootstrapKeys)
	if err != nil {
		return err
	}
	out.Container = c
	out.dbContainer = prepared.dbContainer
	*prepared = *out
	return nil
}

// localKeystorePassword returns the keystore password used to seed and load the bootstrap keystore in
// local mode, matching services.ApplyBootstrapDefaults.
func localKeystorePassword(in *Input) string {
	if in.Bootstrap != nil && in.Bootstrap.Keystore != nil && in.Bootstrap.Keystore.Password != "" {
		return in.Bootstrap.Keystore.Password
	}
	return services.DefaultKeystorePassword
}

func startContainer(ctx context.Context, req testcontainers.ContainerRequest) (testcontainers.Container, error) {
	const maxAttempts = 3
	var c testcontainers.Container
	var lastErr error

	// We need this retry loop because sometimes air will fail to start the server
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var err error
		c, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err == nil {
			return c, nil
		}

		lastErr = err
		framework.L.Warn().Err(err).Int("attempt", attempt).Msg("Container failed to start, retrying...")

		if c != nil {
			_ = services.SaveFailingTestcontainerLogs(ctx, c, req.Name, attempt)
			_ = c.Terminate(ctx)
		}

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	return nil, fmt.Errorf("failed to start container after %d attempts: %w", maxAttempts, lastErr)
}

func baseImageRequest(in *Input, envVars map[string]string, bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath, localAppConfig string) (testcontainers.ContainerRequest, error) {
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		Env: envVars,
		// This is the container port, not the host port, so it can be the same across different containers.
		ExposedPorts: []string{DefaultVerifierPortTCP, services.DefaultBootstrapListenPortTCP},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = network.PortMap{
				network.MustParsePort(DefaultVerifierPortTCP): []network.PortBinding{
					{HostPort: ""}, // Docker assigns a random free host port.
				},
				network.MustParsePort(services.DefaultBootstrapListenPortTCP): []network.PortBinding{
					{HostPort: ""}, // Docker assigns a random free host port.
				},
			}
		},
		WaitingFor: wait.
			ForHTTP(bootstrap.HealthEndpoint).
			WithPort(services.DefaultBootstrapListenPortTCP).
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
	}

	// Mount CA cert for TLS verification if provided. Only our self-signed CA is used for now.
	if in.TLSCACertFile != "" {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			HostFilePath:      in.TLSCACertFile,
			ContainerFilePath: "/etc/ssl/certs/ca-certificates.crt",
			FileMode:          0o644,
		})
	}

	p, err := services.CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return testcontainers.ContainerRequest{}, fmt.Errorf("failed to get source code path: %w", err)
	}

	req.Mounts = testcontainers.Mounts()
	req.Mounts = append(req.Mounts, testcontainers.BindMount(
		bootstrapConfigFilePath,
		bootstrap.DefaultConfigPath,
	))
	// Mount secrets at the default secrets path so the bootstrapper resolves it without an env var,
	// exercising the split config/secrets load path.
	req.Mounts = append(req.Mounts, testcontainers.BindMount(
		bootstrapSecretsFilePath,
		bootstrap.DefaultSecretsPath,
	))
	// Mount the verifier secrets file at its default path so the committee verifier resolves the DB
	// URL and aggregator HMAC credentials from the file, without an env var.
	req.Mounts = append(req.Mounts, testcontainers.BindMount(
		verifierSecretsFilePath,
		vsecrets.DefaultCommitteeVerifierSecretsPath,
	))
	// In local mode the app config is copied into the container image at creation time (present at
	// startup), so the bootstrapper reads a config that already exists rather than waiting for one. The
	// no-JD path builds it after contracts are deployed and passes it here via in.LocalAppConfig.
	if localAppConfig != "" {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			Reader:            strings.NewReader(localAppConfig),
			ContainerFilePath: localAppConfigContainerPath,
			FileMode:          0o644,
		})
	}

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, services.GoSourcePathMounts(in.RootPath, services.AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, services.GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	return req, nil
}

// getAggregatorSecretEntries builds the verifier secrets file's [[aggregators]] entries:
// per-aggregator HMAC credentials keyed by SecretName. AggregatorCredentials is already keyed by
// SecretName, so each key becomes the entry's secret_name — matching config.go's join key. The
// legacy fallback yields a single entry with an omitted secret_name (the default credential).
func getAggregatorSecretEntries(in *Input) ([]vsecrets.AggregatorSecret, error) {
	// Per-aggregator credentials (consolidated topology): the verifier writes to every aggregator in
	// its committee, each with its own credential resolved from the secrets file by secret_name.
	if len(in.AggregatorCredentials) > 0 {
		entries := make([]vsecrets.AggregatorSecret, 0, len(in.AggregatorCredentials))
		for secretName, creds := range in.AggregatorCredentials {
			entries = append(entries, vsecrets.AggregatorSecret{
				SecretName: secretName,
				APIKey:     creds.APIKey,
				SecretKey:  creds.Secret,
			})
		}
		return entries, nil
	}

	// Fallback: a single credential under the legacy default (omitted secret_name).
	var apiKey, secretKey string
	if in.Env != nil && in.Env.AggregatorAPIKey != "" && in.Env.AggregatorSecretKey != "" {
		apiKey = in.Env.AggregatorAPIKey
		secretKey = in.Env.AggregatorSecretKey
	} else if in.AggregatorOutput != nil {
		creds, ok := in.AggregatorOutput.GetCredentialsForClient(in.ContainerName)
		if ok {
			apiKey = creds.APIKey
			secretKey = creds.Secret
		}
	}

	if apiKey == "" || secretKey == "" {
		return nil, fmt.Errorf("failed to get HMAC credentials for verifier %s: no credentials provided via AggregatorCredentials, Env, or AggregatorOutput", in.ContainerName)
	}

	return []vsecrets.AggregatorSecret{{APIKey: apiKey, SecretKey: secretKey}}, nil
}

func dbContainerName(inDBName, chainFamily string) string {
	return fmt.Sprintf("%s-%s", chainFamily, inDBName)
}

func createDBContainer(ctx context.Context, in *Input, chainFamily string) (*postgres.PostgresContainer, error) {
	// Create a temporary file containing the bootstrap init script.
	// This is so that we have two databases created in the database server container, one for the verifier and one for the bootstrap.
	bootstrapInitScriptPath, err := services.CreateBootstrapDBInitScriptFile()
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap init script file: %w", err)
	}

	containerName := dbContainerName(in.DB.Name, chainFamily)
	c, err := postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(containerName),
		postgres.WithDatabase(in.ContainerName),
		postgres.WithUsername(in.ContainerName),
		postgres.WithPassword(in.ContainerName),
		postgres.WithInitScripts(bootstrapInitScriptPath),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name:         containerName,
				ExposedPorts: []string{"5432/tcp"},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {containerName},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = network.PortMap{
						network.MustParsePort("5432/tcp"): []network.PortBinding{
							{HostPort: ""}, // Docker assigns a random free host port.
						},
					}
				},
				WaitingFor: wait.ForAll(
					wait.ForLog("database system is ready to accept connections"),
					wait.ForListeningPort("5432/tcp"),
				),
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	return c, nil
}
