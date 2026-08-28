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

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
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

	// ChainFamily is the chain family that this token verifier reads from.
	// Defaults to "evm" if not specified.
	ChainFamily string `toml:"chain_family"`

	// LombardQualifier identifies which Lombard verifier/resolver deployment this instance's
	// generated config should resolve addresses for.
	LombardQualifier string `toml:"lombard_qualifier"`

	// CCTPQualifier identifies which CCTP verifier/resolver deployment this instance's
	// generated config should resolve addresses for.
	CCTPQualifier string `toml:"cctp_qualifier"`

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

// ReqModifier adjusts a token verifier testcontainers.ContainerRequest for a chain family.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	tokenVerifierInput *TokenVerifierInput,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)

func ApplyTokenVerifierDefaults(in TokenVerifierInput) TokenVerifierInput {
	if in.ChainFamily == "" {
		in.ChainFamily = chainsel.FamilyEVM
	}
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

func NewTokenVerifier(in *TokenVerifierInput, blockchainOutputs []*blockchain.Output, modifiers map[string]ReqModifier) (*TokenVerifierOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	modifier, ok := modifiers[in.ChainFamily]
	if !ok {
		return nil, fmt.Errorf("no token verifier modifier found for chain family %s", in.ChainFamily)
	}

	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
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
	appConfig, err := in.GenerateConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for token verifier %w", err)
	}

	confDir := util.CCVConfigDir()
	appConfigFilePath := filepath.Join(confDir, "token-verifier-app-config.toml")
	if err := os.WriteFile(appConfigFilePath, appConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write token verifier app config to file: %w", err)
	}

	// Generate and write the bootstrap (operator) config. The token verifier runs in local app-config
	// mode with no infra ([db]/[keystore]), so the non-secret config carries only the mode selection,
	// the app-config path, and monitoring (no secrets file); validation correctly skips infra checks.
	bootstrapConfig, err := toml.Marshal(bootstrap.NonSecretConfig{
		AppConfigMode:      bootstrap.AppConfigModeLocal,
		LocalAppConfigPath: "/etc/token-verifier/config.toml",
		Monitoring:         in.Bootstrap.Monitoring,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap config for token verifier: %w", err)
	}
	bootstrapConfigFilePath := filepath.Join(confDir, "token-verifier-bootstrap-config.toml")
	if err := os.WriteFile(bootstrapConfigFilePath, bootstrapConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write token verifier bootstrap config to file: %w", err)
	}

	// Database connection for chain status (internal docker network address). Delivered via the
	// verifier secrets file, mounted at the default path, instead of CL_DATABASE_URL — so
	// e2e exercises the file load path. The token verifier's secrets carry only [db].
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, in.DB.Name, in.ContainerName)
	verifierSecrets, err := GenerateVerifierSecrets(internalDBConnectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token verifier secrets: %w", err)
	}
	verifierSecretsFilePath := filepath.Join(confDir, "token-verifier-secrets.toml")
	// 0o644 (world-readable) matches the bootstrap secrets file: the mounted file must be readable by
	// the `ccv` CLI run via `docker exec`, which may run as a different UID than the bind-mount owner.
	if err := os.WriteFile(verifierSecretsFilePath, verifierSecrets, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write token verifier secrets to file: %w", err)
	}

	// The app-config path is delivered via the bootstrap config's local_app_config_path (set above),
	// not an env var; only the bootstrap config path itself is pointed at via env.
	envVars := make(map[string]string)
	envVars["BOOTSTRAPPER_CONFIG_PATH"] = bootstrap.DefaultConfigPath

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
		WaitingFor: wait.ForLog("Verifier service fully started and ready").
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
	}

	req.Mounts = testcontainers.Mounts()
	req.Mounts = append(req.Mounts,
		testcontainers.BindMount(appConfigFilePath, "/etc/token-verifier/config.toml"),
		testcontainers.BindMount(bootstrapConfigFilePath, bootstrap.DefaultConfigPath),
		testcontainers.BindMount(verifierSecretsFilePath, vsecrets.DefaultTokenVerifierSecretsPath),
	)

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	// Chain-family connection details (e.g. EVM/Solana RPC config) are operator-local
	// configuration, mounted by the family's own modifier — matching the standalone
	// committee verifier and executor paths.
	req, err = modifier(req, in, blockchainOutputs)
	if err != nil {
		return nil, fmt.Errorf("failed to modify request for chain family %s: %w", in.ChainFamily, err)
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

// GenerateConfig serializes only the token-verifier application config. Connection details are
// written to and mounted from the separate chain-family local config.
func (v *TokenVerifierInput) GenerateConfig() (verifierTomlConfig []byte, err error) {
	if v.GeneratedConfig == nil {
		return nil, fmt.Errorf("GeneratedConfig is nil - token verifier config must be generated using changeset before launching")
	}

	cfg, err := toml.Marshal(v.GeneratedConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}
	return cfg, nil
}
