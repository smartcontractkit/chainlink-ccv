package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	ccvblockchain "github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

type TokenVerifierInput struct {
	Mode           Mode                 `toml:"mode"`
	DB             *VerifierDBInput     `toml:"db"`
	Out            *TokenVerifierOutput `toml:"-"`
	Image          string               `toml:"image"`
	SourceCodePath string               `toml:"source_code_path"`
	RootPath       string               `toml:"root_path"`
	ContainerName  string               `toml:"container_name"`
	Port           int                  `toml:"port"`

	// ServiceIdentifier is the identifier for this token verifier service (e.g. "default-token-verifier").
	ServiceIdentifier string `toml:"service_identifier"`
	// PyroscopeURL is the URL of the Pyroscope server for profiling (optional).
	PyroscopeURL string `toml:"pyroscope_url"`
	// Monitoring is the monitoring configuration containing beholder settings.
	Monitoring shared.MonitoringInput `toml:"monitoring"`
	// GeneratedConfig stores the generated token verifier configuration from the changeset.
	GeneratedConfig *token.Config `toml:"-"`
}

type TokenVerifierOutput struct {
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	UseCache           bool   `toml:"use_cache"`
	DBConnectionString string `toml:"db_connection_string"`
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
					h.PortBindings = nat.PortMap{
						"5432/tcp": []nat.PortBinding{
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

	// Generate and store config file.
	config, err := in.GenerateConfigWithBlockchainInfos(blockchainInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for token verifier %w", err)
	}

	confDir := util.CCVConfigDir()
	configFilePath := filepath.Join(confDir, "verifier-config.toml")
	if err := os.WriteFile(configFilePath, config, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write aggregator config to file: %w", err)
	}

	envVars := make(map[string]string)
	// Database connection for chain status (internal docker network address)
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, in.DB.Name, in.ContainerName)
	envVars["CL_DATABASE_URL"] = internalDBConnectionString

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
			h.PortBindings = nat.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				"8100/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.Port)},
				},
			}
		},
		WaitingFor: wait.ForLog("Using real blockchain information from environment").
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
	}

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		req.Mounts = append(req.Mounts, testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			configFilePath,
			aggregator.DefaultConfigFile,
		))
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

func (v *TokenVerifierInput) GenerateConfigWithBlockchainInfos(blockchainInfos map[string]*ccvblockchain.Info) (verifierTomlConfig []byte, err error) {
	if v.GeneratedConfig == nil {
		return nil, fmt.Errorf("GeneratedConfig is nil - token verifier config must be generated using changeset before launching")
	}

	// Use the generated config directly (fake URLs are already injected in environment.go)
	config := token.ConfigWithBlockchainInfos{
		Config:          *v.GeneratedConfig,
		BlockchainInfos: blockchainInfos,
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}
	return cfg, nil
}
