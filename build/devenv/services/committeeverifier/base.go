package committeeverifier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	chainsel "github.com/smartcontractkit/chain-selectors"
	bootstrap "github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvblockchain "github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	DefaultVerifierName    = "verifier"
	DefaultVerifierDBName  = "verifier-db"
	DefaultVerifierImage   = "verifier:dev"
	DefaultVerifierPort    = 8100
	DefaultVerifierPortTCP = "8100/tcp"
	DefaultVerifierDBPort  = 8432
	DefaultVerifierMode    = services.Standalone

	DefaultVerifierDBImage = "postgres:16-alpine"
)

var DefaultVerifierDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultVerifierName, DefaultVerifierName, DefaultVerifierDBPort, DefaultVerifierName)

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

	// CantonConfigs is the map of chain selectors to canton configurations to pass onto the verifier,
	// only used in standalone mode and if Canton is enabled.
	// Note that the full party ID (name + hex) is not expected in the TOML config,
	// just the expected party name.
	// The full party ID is hydrated from the blockchain output after the Canton participant is available.
	CantonConfigs canton.Config `toml:"canton_configs"`

	// DisableFinalityCheckers is a list of chain selectors for which the finality violation checker should be disabled.
	// The chain selectors are formatted as strings of the chain selector.
	DisableFinalityCheckers []string `toml:"disable_finality_checkers"`

	// TLSCACertFile is the path to the CA certificate file for TLS verification.
	TLSCACertFile string `toml:"-"`

	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`

	// AggregatorOutput is optionally set to automatically obtain credentials.
	AggregatorOutput *services.AggregatorOutput `toml:"-"`

	// GeneratedJobSpecs contains all job specs for this verifier, one per aggregator in the committee.
	GeneratedJobSpecs []string `toml:"-"`

	// GeneratedConfig is the verifier configuration TOML derived from
	// GeneratedJobSpecs[NodeIndex % numAggregators].
	// Used in standalone mode. Set by generateVerifierJobSpecs in environment.go.
	GeneratedConfig string `toml:"-"`
}

// RebuildVerifierJobSpecWithBlockchainInfos takes a job spec and rebuilds it with blockchain infos
// added to the inner config. This is needed for standalone verifiers which require blockchain
// connection information (CL nodes get this from their own chain config).
// TODO: we stick with the job spec so that there isn't special logic for standalone verifiers.
func (v *Input) RebuildVerifierJobSpecWithBlockchainInfos(jobSpec string, blockchainInfos map[string]*ccvblockchain.Info) (string, error) {
	// Parse the outer job spec first.
	var spec commit.JobSpec
	if _, err := toml.Decode(jobSpec, &spec); err != nil {
		return "", fmt.Errorf("failed to parse job spec: %w", err)
	}

	// Parse the inner config next.
	var cfg commit.Config
	if _, err := toml.Decode(spec.CommitteeVerifierConfig, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse verifier config from job spec: %w", err)
	}

	// Create config with blockchain infos
	configWithInfos := commit.ConfigWithBlockchainInfos{
		Config:          cfg,
		BlockchainInfos: blockchainInfos,
	}

	// Marshal the enhanced config
	innerConfigBytes, err := toml.Marshal(configWithInfos)
	if err != nil {
		return "", fmt.Errorf("failed to marshal enhanced config: %w", err)
	}

	// Rebuild the job spec with the enhanced config
	spec.CommitteeVerifierConfig = string(innerConfigBytes)
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

func New(in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure) (*Output, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	if jdInfra == nil {
		return nil, fmt.Errorf("JD infrastructure is not set")
	}

	out, err := launchVerifier(ctx, in, outputs, jdInfra)
	if err != nil {
		return nil, fmt.Errorf("failed to launch verifier: %w", err)
	}

	return out, nil
}

func launchVerifier(ctx context.Context, in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure) (*Output, error) {
	// Get the JD server CSA public key
	jdCSAKey, err := jobs.GetJDCSAPublicKey(ctx, jdInfra.OffchainClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get JD server CSA public key: %w", err)
	}

	bootstrap := in.Bootstrap
	dbContainer, err := createDBContainer(ctx, in, in.ChainFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier database: %w", err)
	}

	// Update bootstrap config w/ the database and JD info.
	// TODO: make this easier? All standalone setups will have to do the same thing.
	bootstrap.DB.URL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), services.DefaultBootstrapDBName)
	bootstrap.JD.ServerCSAPublicKey = jdCSAKey
	bootstrap.JD.ServerWSRPCURL = jdInfra.JDOutput.InternalWSRPCUrl

	envVars, err := getAggregatorSecrets(in)
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregator secrets: %w", err)
	}

	// Database connection for chain status (internal docker network address)
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, dbContainerName(in.DB.Name, in.ChainFamily), in.ContainerName)
	envVars["CL_DATABASE_URL"] = internalDBConnectionString

	// Generate and store config file.
	bootstrapConfig, err := services.GenerateBootstrapConfig(*bootstrap)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap config: %w", err)
	}
	confDir := util.CCVConfigDir()
	bootstrapConfigFilePath := filepath.Join(confDir,
		fmt.Sprintf("bootstrap-%s-config-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write bootstrap config to file: %w", err)
	}

	req, err := baseImageRequest(in, envVars, bootstrapConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create base image request: %w", err)
	}

	// Get the modifier for the chain family.
	modifier, ok := modifierPerFamily[in.ChainFamily]
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
	bootstrapKeys, err := services.GetBootstrapKeys(bootstrapURL)
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

	out := &Output{
		ContainerName:   inspect.Name,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%s", host, verifierMapped.Port()),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", inspect.Name, DefaultVerifierPort),
		DBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), in.ContainerName),
		BootstrapDBURL: fmt.Sprintf("http://%s:%s", host, bootstrapMapped.Port()),
		BootstrapDBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%s/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, dbMapped.Port(), services.DefaultBootstrapDBName),
		BootstrapKeys: bootstrapKeys,
	}

	return out, nil
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
			break
		}

		lastErr = err
		framework.L.Warn().Err(err).Int("attempt", attempt).Msg("Container failed to start, retrying...")

		if c != nil {
			_ = c.Terminate(ctx)
		}

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to start container after %d attempts: %w", maxAttempts, lastErr)
	}

	return c, nil
}

func baseImageRequest(in *Input, envVars map[string]string, bootstrapConfigFilePath string) (testcontainers.ContainerRequest, error) {
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
			h.PortBindings = nat.PortMap{
				DefaultVerifierPortTCP: []nat.PortBinding{
					{HostPort: ""}, // Docker assigns a random free host port.
				},
				services.DefaultBootstrapListenPortTCP: []nat.PortBinding{
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

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, services.GoSourcePathMounts(in.RootPath, services.AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, services.GoCacheMounts()...)
		req.Mounts = append(req.Mounts, testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			bootstrapConfigFilePath,
			bootstrap.DefaultConfigPath,
		))
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	return req, nil
}

func getAggregatorSecrets(in *Input) (map[string]string, error) {
	envVars := make(map[string]string)
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
		return nil, fmt.Errorf("failed to get HMAC credentials for verifier %s: no credentials provided via Env or AggregatorOutput", in.ContainerName)
	}

	envVars["VERIFIER_AGGREGATOR_API_KEY"] = apiKey
	envVars["VERIFIER_AGGREGATOR_SECRET_KEY"] = secretKey

	return envVars, nil
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
					h.PortBindings = nat.PortMap{
						"5432/tcp": []nat.PortBinding{
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
