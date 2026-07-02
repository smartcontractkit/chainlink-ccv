package services

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	ccvblockchain "github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultTokenVerifierImage         = "token-verifier:latest"
	DefaultTokenVerifierPort          = 8700
	DefaultTokenVerifierContainerName = "token-verifier-1"
	DefaultTokenVerifierDBImage       = "postgres:16-alpine"
	DefaultTokenVerifierDBName        = "token-verifier-1-db"
	DefaultTokenVerifierDBPort        = 8450
)

//go:embed tokenVerifier.template.toml
var tokenVerifierConfigTemplate string

type TokenVerifierDBInput struct {
	Image string `toml:"image"`
	Name  string `toml:"name"`
	Port  int    `toml:"port"`
}

type TokenVerifierInput struct {
	// Version is the component config schema version (see tokenverifier.Version).
	Version        int                   `toml:"version"`
	Mode           Mode                  `toml:"mode"`
	DB             *TokenVerifierDBInput `toml:"db"`
	Out            *TokenVerifierOutput  `toml:"-"`
	Image          string                `toml:"image"`
	SourceCodePath string                `toml:"source_code_path"`
	RootPath       string                `toml:"root_path"`
	ContainerName  string                `toml:"container_name"`
	Port           int                   `toml:"port"`

	// GeneratedConfig stores the generated token verifier configuration from the changeset.
	GeneratedConfig *token.Config `toml:"-"`

	// Bootstrap is the bootstrap input for the token verifier.
	Bootstrap *BootstrapInput `toml:"bootstrap"`
}

type TokenVerifierOutput struct {
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	UseCache           bool   `toml:"use_cache"`
	DBConnectionString string `toml:"db_connection_string"`
}

func ApplyTokenVerifierDefaults(in TokenVerifierInput) TokenVerifierInput {
	if in.Image == "" {
		in.Image = DefaultTokenVerifierImage
	}
	if in.Port == 0 {
		in.Port = DefaultTokenVerifierPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultTokenVerifierContainerName
	}
	if in.DB == nil {
		in.DB = &TokenVerifierDBInput{
			Image: DefaultTokenVerifierDBImage,
			Name:  DefaultTokenVerifierDBName,
			Port:  DefaultTokenVerifierDBPort,
		}
	}
	if in.Mode == "" {
		in.Mode = Standalone
	}
	if in.Bootstrap == nil {
		def := ApplyBootstrapDefaults(BootstrapInput{})
		in.Bootstrap = &def
	} else {
		def := ApplyBootstrapDefaults(*in.Bootstrap)
		in.Bootstrap = &def
	}
	return in
}

func NewTokenVerifier(in *TokenVerifierInput, blockchainOutputs []*blockchain.Output) (*TokenVerifierOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Generate blockchain infos for standalone mode
	blockchainInfos, err := ConvertBlockchainOutputsToInfo(blockchainOutputs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate blockchain infos from blockchain outputs: %w", err)
	}

	/* Database */
	_, err = postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(in.DB.Name),
		postgres.WithDatabase(in.ContainerName),
		postgres.WithUsername(in.ContainerName),
		postgres.WithPassword(in.ContainerName),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name:         in.DB.Name,
				ExposedPorts: []string{"5432/tcp"},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {in.DB.Name},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = network.PortMap{
						network.MustParsePort("5432/tcp"): []network.PortBinding{
							{HostPort: strconv.Itoa(in.DB.Port)},
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

	// Generate and write the app config.
	appConfig, err := in.GenerateConfigWithBlockchainInfos(blockchainInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for token verifier %w", err)
	}

	confDir := util.CCVConfigDir()
	appConfigFilePath := filepath.Join(confDir, "token-verifier-app-config.toml")
	if err := os.WriteFile(appConfigFilePath, appConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write token verifier app config to file: %w", err)
	}

	// Generate and write the bootstrap (operator) config, carrying monitoring from the generated config.
	// Only the monitoring section is set; the infra sections (jd/db/keystore/server) are zero-valued
	// and omitted from the TOML output via omitempty, so validation correctly skips infra checks.
	bootstrapConfig, err := toml.Marshal(bootstrap.Config{Monitoring: in.Bootstrap.Monitoring})
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap config for token verifier: %w", err)
	}
	bootstrapConfigFilePath := filepath.Join(confDir, "token-verifier-bootstrap-config.toml")
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write token verifier bootstrap config to file: %w", err)
	}

	envVars := make(map[string]string)
	// Database connection for chain status (internal docker network address)
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, in.DB.Name, in.ContainerName)
	envVars["CL_DATABASE_URL"] = internalDBConnectionString
	envVars["TOKEN_VERIFIER_CONFIG_PATH"] = "/etc/token-verifier-app-config.toml"
	envVars["BOOTSTRAPPER_CONFIG_PATH"] = bootstrap.DefaultConfigPath
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		envVars["LOG_LEVEL"] = lvl
	}

	/* Service */
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		Env: envVars,
		// ExposedPorts
		// add more internal ports here with /tcp suffix, ex.: 9222/tcp
		ExposedPorts: []string{"8100/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = network.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				network.MustParsePort("8100/tcp"): []network.PortBinding{
					{HostPort: strconv.Itoa(in.Port)},
				},
			}
		},
		WaitingFor: wait.ForLog("Using real blockchain information from environment").
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
	}

	req.Mounts = testcontainers.Mounts()
	req.Mounts = append(req.Mounts,
		testcontainers.BindMount(appConfigFilePath, "/etc/token-verifier-app-config.toml"),
		testcontainers.BindMount(bootstrapConfigFilePath, bootstrap.DefaultConfigPath),
	)

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	const maxAttempts = 3
	var c testcontainers.Container
	var lastErr error

	// We need this retry loop because sometimes air will fail to start the server
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err == nil {
			lastErr = nil
			break
		}

		lastErr = err
		framework.L.Warn().Err(err).Int("attempt", attempt).Msg("Container failed to start, retrying...")

		if c != nil {
			_ = SaveFailingTestcontainerLogs(ctx, c, in.ContainerName, attempt)
			_ = c.Terminate(ctx)
		}

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to start container after %d attempts: %w", maxAttempts, lastErr)
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	return &TokenVerifierOutput{
		ContainerName:   in.ContainerName,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
		DBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, in.DB.Port, in.ContainerName),
	}, nil
}

func (v *TokenVerifierInput) GenerateConfigWithBlockchainInfos(blockchainInfos ccvblockchain.Infos[evm.Info]) (verifierTomlConfig []byte, err error) {
	if v.GeneratedConfig == nil {
		return nil, fmt.Errorf("GeneratedConfig is nil - token verifier config must be generated using changeset before launching")
	}

	anyInfo := make(ccvblockchain.Infos[any])
	for k, info := range blockchainInfos {
		anyInfo[k] = info
	}

	// Use the generated config directly (fake URLs are already injected in environment.go)
	config := token.ConfigWithBlockchainInfos{
		Config:          *v.GeneratedConfig,
		BlockchainInfos: anyInfo,
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}
	return cfg, nil
}

func (v *TokenVerifierInput) GenerateTemplateConfig() (*token.Config, error) {
	var config *token.Config
	if _, err := toml.Decode(tokenVerifierConfigTemplate, &config); err != nil {
		return nil, fmt.Errorf("failed to decode verifier config template: %w", err)
	}
	return config, nil
}
