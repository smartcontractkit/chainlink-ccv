package executor

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
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	DefaultExecutorName    = "executor"
	DefaultExecutorImage   = "executor:latest"
	DefaultExecutorPort    = 8101
	DefaultExecutorPortTCP = "8101/tcp"
	DefaultExecutorMode    = services.Standalone

	DefaultExecutorDBImage = "postgres:16-alpine"

	// localAppConfigContainerPath is where the local-mode app config lives inside the container (written
	// into the bootstrap config as local_app_config_path). It is copied into the container image at
	// creation time (testcontainers Files), so it is present before the bootstrapper starts.
	localAppConfigContainerPath = "/etc/executor-app.toml"
)

// ReqModifier modifies an executor testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	executorInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)

type Input struct {
	// Version is the component config schema version (see the executor
	// component's Version constant).
	Version        int           `toml:"version"`
	Mode           services.Mode `toml:"mode"`
	Out            *Output       `toml:"out"`
	Image          string        `toml:"image"`
	SourceCodePath string        `toml:"source_code_path"`
	RootPath       string        `toml:"root_path"`
	ContainerName  string        `toml:"container_name"`
	NOPAlias       string        `toml:"nop_alias"`
	UseCache       bool          `toml:"use_cache"`

	// ChainFamily is the chain family that we should launch an executor for.
	// Defaults to "evm" if not specified.
	ChainFamily string `toml:"chain_family"`

	// ExecutorQualifier is the qualifier for the executor contract.
	ExecutorQualifier string `toml:"executor_qualifier"`

	// GeneratedJobSpecs contains all job specs for this executor.
	GeneratedJobSpecs []string `toml:"-"`

	// Bootstrap is the bootstrap configuration for bootstrapped mode.
	Bootstrap *services.BootstrapInput `toml:"bootstrap"`

	// DB is the database configuration.
	DB *DBInput `toml:"db"`

	// LocalAppConfig is the plain app-config TOML mounted into the container in local mode
	// (services.Local). When set, it is copied into the container at creation so the bootstrapper reads
	// a config present at boot. The no-JD devenv environment does not use this single-shot field; it
	// uses the two-phase PrepareLocal / LaunchLocalWithConfig flow (config built after contracts deploy).
	LocalAppConfig string `toml:"-"`
}

type DBInput struct {
	Image string `toml:"image"`
	Name  string `toml:"name"`
}

type Output struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPURL string `toml:"http_url"`
	InternalHTTPURL string `toml:"internal_http_url"`
	UseCache        bool   `toml:"use_cache"`

	// Bootstrap outputs (only populated in bootstrapped mode)
	BootstrapDBURL              string                 `toml:"bootstrap_db_url"`
	BootstrapDBConnectionString string                 `toml:"bootstrap_db_connection_string"`
	BootstrapKeys               services.BootstrapKeys `toml:"bootstrap_keys"`

	// JDNodeID is set after the bootstrap is registered with JD.
	JDNodeID string `toml:"jd_node_id"`

	// Container is the running executor container, retained in local mode. Not serialized. Nil until the
	// container is started (in the no-JD two-phase path, nil after PrepareLocal and set by
	// LaunchLocalWithConfig).
	Container testcontainers.Container `toml:"-"`

	// dbContainer is the bootstrap Postgres container, created by PrepareLocal before the main container
	// so its keystore can be seeded, and reused by LaunchLocalWithConfig to resolve the mapped DB port.
	// Not serialized. Only set on the no-JD two-phase local path.
	dbContainer testcontainers.Container `toml:"-"`
}

// configWithBlockchainInfos is the executor config plus the blockchain_infos section (RPC URLs etc.).
// Standalone/local executors need blockchain_infos inlined because, unlike CL-mode executors, they
// have no CL node to source chain connection info from.
type configWithBlockchainInfos struct {
	executor.Configuration
	BlockchainInfos chainaccess.Infos[any] `toml:"blockchain_infos"`
}

// BuildExecutorAppConfigWithBlockchainInfos parses the executor config out of a job spec and
// re-marshals it with blockchain_infos included, returning the plain app-config TOML — the exact
// content JD ships as a job's appConfig, with no job-spec envelope. This is what a local-mode
// bootstrapper reads from its mounted config file.
func BuildExecutorAppConfigWithBlockchainInfos(spec bootstrap.JobSpec, blockchainInfos map[string]any) (string, error) {
	var cfg executor.Configuration
	if err := spec.GetAppConfig(&cfg); err != nil {
		return "", fmt.Errorf("failed to parse executor config from job spec: %w", err)
	}
	innerConfigBytes, err := toml.Marshal(configWithBlockchainInfos{
		Configuration:   cfg,
		BlockchainInfos: blockchainInfos,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal enhanced config: %w", err)
	}
	return string(innerConfigBytes), nil
}

// RebuildExecutorJobSpecWithBlockchainInfos takes a job spec and rebuilds it with blockchain infos
// added to the inner config. This is needed for standalone executors which require blockchain
// connection information (CL nodes get this from their own chain config).
func RebuildExecutorJobSpecWithBlockchainInfos(spec bootstrap.JobSpec, blockchainInfos map[string]any) (string, error) {
	innerConfig, err := BuildExecutorAppConfigWithBlockchainInfos(spec, blockchainInfos)
	if err != nil {
		return "", err
	}

	spec.AppConfig = innerConfig
	outerSpecBytes, err := toml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal job spec: %w", err)
	}

	return string(outerSpecBytes), nil
}

func ApplyDefaults(in *Input) {
	if in.Image == "" {
		in.Image = DefaultExecutorImage
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultExecutorName
	}
	if in.Mode == "" {
		in.Mode = DefaultExecutorMode
	}
	if in.ChainFamily == "" {
		in.ChainFamily = chainsel.FamilyEVM
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image: DefaultExecutorDBImage,
			Name:  in.ContainerName + "-db",
		}
	}
	if in.Bootstrap == nil {
		def := services.ApplyBootstrapDefaults(services.BootstrapInput{})
		in.Bootstrap = &def
	} else {
		def := services.ApplyBootstrapDefaults(*in.Bootstrap)
		in.Bootstrap = &def
	}
}

// New creates an executor managed by JD via bootstrap.Run.
//
// transmitterKeyName is the bootstrap keystore key name whose on-chain address
// must be fetched and funded for this chain family. It is resolved by the caller
// from the chain registry (chainreg) so that this service package does not import
// chainreg (cycle). Pass "" for families that have no bootstrap-managed transmitter key.
func New(in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier, transmitterKeyName string) (*Output, error) {
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

	out, err := launchExecutor(ctx, in, outputs, jdInfra, modifiers, transmitterKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to launch executor: %w", err)
	}

	return out, nil
}

func launchExecutor(ctx context.Context, in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier, transmitterKeyName string) (*Output, error) {
	// local mode runs without JD: the app config is delivered via a mounted file rather than a JD job
	// proposal, so all JD wiring below is skipped.
	local := in.Mode == services.Local

	bs := in.Bootstrap
	dbContainer, err := createDBContainer(ctx, in, in.ChainFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor database: %w", err)
	}

	bs.DB.URL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), services.DefaultBootstrapDBName)

	if !local {
		// Point the bootstrapper at JD. In local mode [jd] is left blank and the mode/app-config path
		// are set instead.
		jdCSAKey, err := jobs.GetJDCSAPublicKey(ctx, jdInfra.OffchainClient)
		if err != nil {
			return nil, fmt.Errorf("failed to get JD server CSA public key: %w", err)
		}
		bs.JD.ServerCSAPublicKey = jdCSAKey
		bs.JD.ServerWSRPCURL = jdInfra.JDOutput.InternalWSRPCUrl
	} else {
		bs.AppConfigMode = bootstrap.AppConfigModeLocal
		bs.LocalAppConfigPath = localAppConfigContainerPath
	}

	bootstrapConfigFilePath, bootstrapSecretsFilePath, err := generateExecutorConfigFiles(in, bs)
	if err != nil {
		return nil, err
	}

	req, err := baseImageRequest(in, bootstrapConfigFilePath, bootstrapSecretsFilePath, in.LocalAppConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base image request: %w", err)
	}

	modifier, ok := modifiers[in.ChainFamily]
	if !ok {
		return nil, fmt.Errorf("no modifier found for chain family %s", in.ChainFamily)
	}

	framework.L.Info().
		Str("Service", in.ContainerName).
		Str("ChainFamily", in.ChainFamily).
		Msg("Using modifier for chain family")

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

	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	bootstrapMapped, err := c.MappedPort(ctx, services.DefaultBootstrapListenPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap mapped port: %w", err)
	}
	bootstrapURL := fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port())

	// Fetches the CSA key and the family-specific transmitter key (resolved by the
	// caller from chainreg) from the bootstrap server. The CSA key is used for JD
	// registration, the transmitter key is used to derive the on-chain address that
	// must be funded before the executor can submit transactions. (The local two-phase path seeds these
	// keys instead — see PrepareLocal.)
	keyNames := []string{bootstrap.DefaultCSAKeyName}
	if transmitterKeyName != "" {
		keyNames = append(keyNames, transmitterKeyName)
	}
	bootstrapKeys, err := services.FetchBootstrapKeys(bootstrapURL, keyNames...)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap keys: %w", err)
	}

	out, err := finalizeExecutorOutput(ctx, c, dbContainer, in, bootstrapKeys)
	if err != nil {
		return nil, err
	}
	if local {
		out.Container = c
	}
	return out, nil
}

// generateExecutorConfigFiles writes the bootstrap config and secrets files for the executor and
// returns their paths. Shared by the JD and local launch paths.
func generateExecutorConfigFiles(in *Input, bs *services.BootstrapInput) (bootstrapConfigFilePath, bootstrapSecretsFilePath string, err error) {
	bootstrapConfig, err := services.GenerateBootstrapConfig(*bs)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate bootstrap config: %w", err)
	}
	bootstrapSecrets, err := services.GenerateBootstrapSecrets(*bs)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate bootstrap secrets: %w", err)
	}
	confDir := util.CCVConfigDir()
	bootstrapConfigFilePath = filepath.Join(confDir,
		fmt.Sprintf("bootstrap-executor-%s-config.toml", in.ContainerName))
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return "", "", fmt.Errorf("failed to write bootstrap config to file: %w", err)
	}
	bootstrapSecretsFilePath = filepath.Join(confDir,
		fmt.Sprintf("bootstrap-executor-%s-secrets.toml", in.ContainerName))
	if err := os.WriteFile(bootstrapSecretsFilePath, bootstrapSecrets, 0o644); err != nil {
		return "", "", fmt.Errorf("failed to write bootstrap secrets to file: %w", err)
	}
	return bootstrapConfigFilePath, bootstrapSecretsFilePath, nil
}

// finalizeExecutorOutput resolves the running container's mapped ports and builds the executor Output.
// bootstrapKeys are supplied by the caller (fetched in JD mode, seeded up front in the local two-phase
// path). Shared by launchExecutor and LaunchLocalWithConfig.
func finalizeExecutorOutput(ctx context.Context, c, dbContainer testcontainers.Container, in *Input, bootstrapKeys services.BootstrapKeys) (*Output, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}
	bootstrapMapped, err := c.MappedPort(ctx, services.DefaultBootstrapListenPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap mapped port: %w", err)
	}
	executorMapped, err := c.MappedPort(ctx, DefaultExecutorPortTCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor mapped port: %w", err)
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
		ExternalHTTPURL: fmt.Sprintf("http://%s:%s", host, executorMapped.Port()),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", containerName, DefaultExecutorPort),
		BootstrapDBURL:  fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port()),
		BootstrapDBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName),
		BootstrapKeys: bootstrapKeys,
	}, nil
}

// PrepareLocal starts the executor's bootstrap Postgres and seeds its signing keys (CSA + the
// family-specific transmitter key), without starting the executor container. It returns an Output
// whose BootstrapKeys are populated — so the no-JD environment can fund the transmitter address before
// any executor container runs — and whose bootstrap DB container is retained for LaunchLocalWithConfig.
func PrepareLocal(ctx context.Context, in *Input, outputs []*blockchain.Output, transmitterKeyName string) (*Output, error) {
	if in.Mode != services.Local {
		return nil, fmt.Errorf("PrepareLocal requires local mode, got %q", in.Mode)
	}
	dbContainer, err := createDBContainer(ctx, in, in.ChainFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor database: %w", err)
	}
	dbMapped, err := dbContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to get database mapped port: %w", err)
	}
	seedDBURL := fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName)
	specs := []services.KeySpec{{Name: bootstrap.DefaultCSAKeyName, Purpose: "csa", Type: keystore.Ed25519}}
	if transmitterKeyName != "" {
		specs = append(specs, services.KeySpec{Name: transmitterKeyName, Purpose: "transmitting", Type: keystore.ECDSA_S256})
	}
	bootstrapKeys, err := services.SeedBootstrapKeys(ctx, seedDBURL, localKeystorePassword(in), specs)
	if err != nil {
		return nil, fmt.Errorf("failed to seed executor keys: %w", err)
	}
	return &Output{BootstrapKeys: bootstrapKeys, dbContainer: dbContainer}, nil
}

// LaunchLocalWithConfig starts the executor container prepared by PrepareLocal, with the app config
// mounted so it is present at startup. It reuses the seeded keystore (prepared.BootstrapKeys) and the
// bootstrap DB created by PrepareLocal, so no keys are fetched from the container. appConfigTOML is the
// executor's app config (with blockchain_infos), built after contracts are deployed. On success it
// populates prepared in place with the running container's outputs.
func LaunchLocalWithConfig(ctx context.Context, prepared *Output, in *Input, outputs []*blockchain.Output, modifiers map[string]ReqModifier, appConfigTOML string) error {
	if prepared == nil || prepared.dbContainer == nil {
		return fmt.Errorf("executor was not prepared for local mode (call PrepareLocal first)")
	}

	bs := in.Bootstrap
	bs.DB.URL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), services.DefaultBootstrapDBName)
	bs.AppConfigMode = bootstrap.AppConfigModeLocal
	bs.LocalAppConfigPath = localAppConfigContainerPath

	bootstrapConfigFilePath, bootstrapSecretsFilePath, err := generateExecutorConfigFiles(in, bs)
	if err != nil {
		return err
	}

	req, err := baseImageRequest(in, bootstrapConfigFilePath, bootstrapSecretsFilePath, appConfigTOML)
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

	out, err := finalizeExecutorOutput(ctx, c, prepared.dbContainer, in, prepared.BootstrapKeys)
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

func baseImageRequest(in *Input, bootstrapConfigFilePath, bootstrapSecretsFilePath, localAppConfig string) (testcontainers.ContainerRequest, error) {
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		ExposedPorts: []string{DefaultExecutorPortTCP, services.DefaultBootstrapListenPortTCP},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = network.PortMap{
				network.MustParsePort(DefaultExecutorPortTCP): []network.PortBinding{
					{HostPort: ""},
				},
				network.MustParsePort(services.DefaultBootstrapListenPortTCP): []network.PortBinding{
					{HostPort: ""},
				},
			}
		},
		WaitingFor: wait.
			ForHTTP(bootstrap.HealthEndpoint).
			WithPort(services.DefaultBootstrapListenPortTCP).
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
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
	// In local mode the app config is copied into the container image at creation time (present at
	// startup) so the bootstrapper reads a config that already exists. The no-JD path builds it after
	// contracts are deployed and passes it here via in.LocalAppConfig.
	if localAppConfig != "" {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			Reader:            strings.NewReader(localAppConfig),
			ContainerFilePath: localAppConfigContainerPath,
			FileMode:          0o644,
		})
	}

	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, services.GoSourcePathMounts(in.RootPath, services.AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, services.GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	return req, nil
}

func dbContainerName(inDBName, chainFamily string) string {
	return fmt.Sprintf("%s-%s", chainFamily, inDBName)
}

func createDBContainer(ctx context.Context, in *Input, chainFamily string) (*postgres.PostgresContainer, error) {
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
							{HostPort: ""},
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
