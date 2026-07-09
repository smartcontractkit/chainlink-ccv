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

	// localAppConfigContainerDir is the directory bind-mounted into the container in local mode, and
	// localAppConfigContainerPath is the app-config file within it (written into the bootstrap config as
	// local_app_config_path). A directory is mounted rather than a single file so devenv can deliver the
	// config AFTER the container starts (the bootstrapper waits for the file to appear): a file bind
	// mount pins one host inode, so a later atomic rewrite would not be visible, whereas a new file
	// appearing in a mounted directory is.
	localAppConfigContainerDir  = "/etc/executor-app"
	localAppConfigContainerPath = localAppConfigContainerDir + "/app.toml"
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
	// (services.Local). Optional: when empty, the container starts serving keys and waits for the
	// config to be delivered later via Output.LocalAppConfigHostPath (the no-JD devenv path, where the
	// executor config is generated after contracts are deployed). When set, it is written at launch.
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

	// LocalAppConfigHostPath is the host path of the app-config file bind-mounted into the container in
	// local mode. When the config is delivered after launch (no-JD path), the caller writes this path
	// via DeliverLocalAppConfig and the waiting bootstrapper picks it up. Empty outside local mode.
	LocalAppConfigHostPath string `toml:"local_app_config_host_path"`
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

// DeliverLocalAppConfig writes the app-config TOML to the host path bind-mounted into a local-mode
// executor container, so the waiting bootstrapper starts the service. Used by the no-JD devenv path,
// which generates the executor config after contracts are deployed.
func DeliverLocalAppConfig(out *Output, appConfigTOML string) error {
	if out == nil {
		return fmt.Errorf("executor output is nil; was it launched in local mode?")
	}
	return services.WriteLocalAppConfigFile(out.LocalAppConfigHostPath, appConfigTOML)
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

	// In local mode, the bootstrapper reads the app config from a mounted directory (see
	// localAppConfigContainerDir); the config may be written now (in.LocalAppConfig) or delivered later
	// via Output.LocalAppConfigHostPath.
	var localAppConfigHostDir, localAppConfigHostFile string
	if local {
		confDir := util.CCVConfigDir()
		localAppConfigHostDir = filepath.Join(confDir, fmt.Sprintf("executor-%s-appdir", in.ContainerName))
		if err := os.MkdirAll(localAppConfigHostDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create local app config dir: %w", err)
		}
		localAppConfigHostFile = filepath.Join(localAppConfigHostDir, "app.toml")
		if in.LocalAppConfig != "" {
			if err := os.WriteFile(localAppConfigHostFile, []byte(in.LocalAppConfig), 0o644); err != nil {
				return nil, fmt.Errorf("failed to write local app config to file: %w", err)
			}
		}
	}

	bootstrapConfig, err := services.GenerateBootstrapConfig(*bs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap config: %w", err)
	}
	bootstrapSecrets, err := services.GenerateBootstrapSecrets(*bs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap secrets: %w", err)
	}
	confDir := util.CCVConfigDir()
	bootstrapConfigFilePath := filepath.Join(confDir,
		fmt.Sprintf("bootstrap-executor-%s-config.toml", in.ContainerName))
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write bootstrap config to file: %w", err)
	}
	bootstrapSecretsFilePath := filepath.Join(confDir,
		fmt.Sprintf("bootstrap-executor-%s-secrets.toml", in.ContainerName))
	if err := os.WriteFile(bootstrapSecretsFilePath, bootstrapSecrets, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write bootstrap secrets to file: %w", err)
	}

	req, err := baseImageRequest(in, bootstrapConfigFilePath, bootstrapSecretsFilePath, localAppConfigHostDir)
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
	// must be funded before the executor can submit transactions.
	keyNames := []string{bootstrap.DefaultCSAKeyName}
	if transmitterKeyName != "" {
		keyNames = append(keyNames, transmitterKeyName)
	}
	bootstrapKeys, err := services.FetchBootstrapKeys(bootstrapURL, keyNames...)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap keys: %w", err)
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
	out := &Output{
		ContainerName:   inspect.Name,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%s", host, executorMapped.Port()),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", containerName, DefaultExecutorPort),
		BootstrapDBURL:  fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port()),
		BootstrapDBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName),
		BootstrapKeys:          bootstrapKeys,
		LocalAppConfigHostPath: localAppConfigHostFile,
	}

	return out, nil
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

func baseImageRequest(in *Input, bootstrapConfigFilePath, bootstrapSecretsFilePath, localAppConfigHostDir string) (testcontainers.ContainerRequest, error) {
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
	// Local mode: mount the app-config directory so the bootstrapper reads local_app_config_path
	// (localAppConfigContainerDir/app.toml). A directory (not a file) is mounted so a config delivered
	// after startup — the no-JD path — becomes visible in the container.
	if localAppConfigHostDir != "" {
		req.Mounts = append(req.Mounts, testcontainers.BindMount(
			localAppConfigHostDir,
			localAppConfigContainerDir,
		))
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
