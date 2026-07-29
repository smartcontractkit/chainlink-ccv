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
	// into the bootstrap config as local_app_config_path). It sits directly under /etc (which always
	// exists) and is delivered by copying the file into the running container (see DeliverLocalAppConfig)
	// rather than via a bind mount: post-startup delivery then works identically on every Docker host
	// (local, CI, remote daemon), where host-side writes into a bind-mounted directory do not reliably
	// propagate into an already-running container.
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
	// (services.Local) — the same typed committee verifier config JD would ship in a job's
	// appConfig, with no job-spec envelope.
	//
	// It is optional in local mode: when empty, the container starts with no app config and the
	// bootstrapper serves its signing keys while waiting for the file to appear; the caller delivers the
	// config later by writing Output.LocalAppConfigHostPath (see DeliverLocalAppConfig). This is how the
	// no-JD devenv path (app_config_source = "local") mirrors JD's deliver-config-after-connect flow:
	// the verifier's signer must be readable before contracts are configured, but its config isn't
	// known until after they are deployed.
	LocalAppConfig string `toml:"-"`
}

// BuildVerifierAppConfig parses and re-marshals the typed verifier config from a job spec. The
// returned app config intentionally excludes blockchain_infos: chain-family connection details are
// supplied through local config in standalone/local mode or node config in CL mode.
func BuildVerifierAppConfig(spec bootstrap.JobSpec) (string, error) {
	var cfg commit.Config
	if err := spec.GetAppConfig(&cfg); err != nil {
		return "", fmt.Errorf("failed to parse verifier config from job spec: %w", err)
	}
	innerConfigBytes, err := toml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal verifier config: %w", err)
	}
	return string(innerConfigBytes), nil
}

// RebuildVerifierJobSpec rebuilds a parsed job spec without adding operator-owned chain config.
// TODO: we stick with the job spec so that there isn't special logic for standalone verifiers.
func RebuildVerifierJobSpec(spec bootstrap.JobSpec) (string, error) {
	innerConfig, err := BuildVerifierAppConfig(spec)
	if err != nil {
		return "", err
	}

	// Preserve the envelope field the deployment chose for this NOP's mode: standalone specs use
	// appConfig (read by the local bootstrapper), cl-mode/default specs use committeeVerifierConfig
	// (required by the CL node's ccvcommitteeverifier job validation). Emitting a fixed field would
	// break one of the two flows and cause spec drift against the deployment-generated spec.
	configField := spec.ConfigFieldName
	if configField == "" {
		configField = "appConfig"
	}

	// Match the exact envelope the deployment emits (see ApplyVerifierConfig) so the rebuilt spec
	// round-trips through ParseVerifierBootstrapJobSpec and matches on drift comparison.
	return fmt.Sprintf(`schemaVersion = %d
type = "%s"
name = "%s"
externalJobID = "%s"
%s = '''
%s'''
`, spec.SchemaVersion, spec.Type, spec.Name, spec.ExternalJobID, configField, innerConfig), nil
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

	// Container is the running verifier container, retained in local mode so the app config can be
	// copied in after startup (DeliverLocalAppConfig) — the no-JD path delivers config once contracts
	// are deployed. Not serialized. Nil outside local mode.
	Container testcontainers.Container `toml:"-"`
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

	aggregatorSecrets, err := getAggregatorSecretEntries(in)
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregator secrets: %w", err)
	}

	// Database connection for chain status (internal docker network address).
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), in.ContainerName)

	// Deliver the DB URL and per-aggregator HMAC credentials via the verifier secrets file,
	// mounted at the default path, instead of the CL_DATABASE_URL / VERIFIER_AGGREGATOR_* env vars —
	// so e2e exercises the file load path.
	verifierSecrets, err := services.GenerateVerifierSecrets(internalDBConnectionString, aggregatorSecrets)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier secrets: %w", err)
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
		return nil, fmt.Errorf("failed to generate bootstrap config: %w", err)
	}
	bootstrapSecrets, err := services.GenerateBootstrapSecrets(*bootstrapInput)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap secrets: %w", err)
	}
	confDir := util.CCVConfigDir()
	bootstrapConfigFilePath := filepath.Join(confDir,
		fmt.Sprintf("bootstrap-%s-config-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write bootstrap config to file: %w", err)
	}
	bootstrapSecretsFilePath := filepath.Join(confDir,
		fmt.Sprintf("bootstrap-%s-secrets-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(bootstrapSecretsFilePath, bootstrapSecrets, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write bootstrap secrets to file: %w", err)
	}
	verifierSecretsFilePath := filepath.Join(confDir,
		fmt.Sprintf("verifier-%s-secrets-%d.toml", in.CommitteeName, in.NodeIndex+1))
	// 0o644 (world-readable) matches the bootstrap secrets file: the mounted file must be readable by
	// the `ccv` CLI run via `docker exec`, which may run as a different UID than the bind-mount owner.
	if err := os.WriteFile(verifierSecretsFilePath, verifierSecrets, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write verifier secrets to file: %w", err)
	}

	// In local mode the bootstrapper reads the app config from a file at local_app_config_path. It is
	// delivered by copying it into the running container (below / DeliverLocalAppConfig), not via a bind
	// mount, so the container boots serving keys and the config can arrive at launch (in.LocalAppConfig
	// set) or later (no-JD path: once contracts are deployed and the config is known).
	req, err := baseImageRequest(in, nil, bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath)
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

	// Local mode with a config known at launch: copy it in now so the waiting bootstrapper starts the
	// service. When no config is provided (no-JD path), it is delivered later via DeliverLocalAppConfig.
	if local && in.LocalAppConfig != "" {
		if err := services.CopyLocalAppConfigToContainer(ctx, c, localAppConfigContainerPath, in.LocalAppConfig); err != nil {
			return nil, fmt.Errorf("failed to deliver local app config: %w", err)
		}
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	// Get the generated CSA key from the bootstrap server.
	bootstrapMapped, err := c.MappedPort(ctx, services.DefaultBootstrapListenPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap mapped port: %w", err)
	}
	bootstrapURL := fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port())

	// Fetches the CSA and ECDSA keys from the bootstrap server.
	// Verifiers need both for JD registration and committee signer registration.
	bootstrapKeys, err := services.FetchBootstrapKeys(bootstrapURL, bootstrap.DefaultCSAKeyName, commit.DefaultECDSASigningKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap keys: %w", err)
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
	out := &Output{
		ContainerName:   inspect.Name,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%s", host, verifierMapped.Port()),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", containerName, DefaultVerifierPort),
		DBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), in.ContainerName),
		BootstrapDBURL: fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port()),
		BootstrapDBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName),
		BootstrapKeys: bootstrapKeys,
	}
	if local {
		out.Container = c
	}
	if local && in.LocalAppConfig != "" {
		if err := services.WaitForApplicationReady(ctx, out.BootstrapDBURL, services.DefaultApplicationReadyTimeout); err != nil {
			return nil, fmt.Errorf("verifier application did not become ready: %w", err)
		}
	}

	return out, nil
}

// DeliverLocalAppConfig copies the app-config TOML into a running local-mode verifier container at
// local_app_config_path and waits for the application factory to start. Copying into the container
// (rather than writing a bind-mounted host file) makes post-startup delivery work on every Docker
// host. Used by the no-JD devenv path, which cannot supply the config at launch because it depends on
// contract addresses deployed after the verifier is up.
func DeliverLocalAppConfig(out *Output, appConfigTOML string) error {
	if out == nil || out.Container == nil {
		return fmt.Errorf("verifier output has no running container; was it launched in local mode?")
	}
	if err := services.CopyLocalAppConfigToContainer(context.Background(), out.Container, localAppConfigContainerPath, appConfigTOML); err != nil {
		return err
	}
	return services.WaitForApplicationReady(context.Background(), out.BootstrapDBURL, services.DefaultApplicationReadyTimeout)
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

func baseImageRequest(in *Input, envVars map[string]string, bootstrapConfigFilePath, bootstrapSecretsFilePath, verifierSecretsFilePath string) (testcontainers.ContainerRequest, error) {
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

	// Exported Chainlink node keys, present only during a CL-to-standalone cutover. The paths here
	// are the ones the generated bootstrap config's [[key_imports]] entries name; both come from
	// services.BuildKeyImports.
	if in.Bootstrap != nil {
		req.Files = append(req.Files, in.Bootstrap.KeyImportFiles...)
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
	// Note: in local mode the app config is delivered by copying it into the running container
	// (see DeliverLocalAppConfig), not via a bind mount.

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
