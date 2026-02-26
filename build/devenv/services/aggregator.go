package services

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/configuration"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

//go:embed aggregator.template.toml
var aggregatorConfigTemplate string

const (
	AggregatorContainerNameSuffix = "aggregator"

	// Redis constants.
	AggregatorRedisContainerNameSuffix = "aggregator-redis"
	DefaultRedisContainerPort          = "6379/tcp"

	// PostgreSQL constants.
	AggregatorDBContainerNameSuffix = "aggregator-db"
	DefaultAggregatorDBUsername     = "aggregator"
	DefaultAggregatorDBPassword     = "aggregator"
	DefaultAggregatorDBName         = "aggregator"
	DefaultDBContainerPort          = "5432/tcp"
	DefaultAggregatorSQLInit        = "init.sql"

	// Nginx TLS proxy constants.
	AggregatorNginxContainerNameSuffix = "aggregator-nginx"
	DefaultNginxImage                  = "nginx:alpine"
	DefaultNginxTLSPort                = "443/tcp"
	DefaultAggregatorGRPCPort          = 50051
)

type AggregatorDBInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the database will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
}

type AggregatorRedisInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the redis will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
}

type AggregatorEnvConfig struct {
	StorageConnectionURL string `toml:"storage_connection_url"`
	RedisAddress         string `toml:"redis_address"`
	RedisPassword        string `toml:"redis_password"`
	RedisDB              string `toml:"redis_db"`
}

type AggregatorAPIKeyPair struct {
	APIKey string `toml:"api_key"`
	Secret string `toml:"secret"`
}
type AggregatorClientConfig struct {
	ClientID    string                  `toml:"client_id"`
	Description string                  `toml:"description"`
	Enabled     bool                    `toml:"enabled"`
	Groups      []string                `toml:"groups"`
	APIKeyPairs []*AggregatorAPIKeyPair `toml:"api_key_pairs"`
}

type AggregatorInput struct {
	Image string `toml:"image"`
	// Name is the unique instance identifier for this aggregator.
	// Used for container naming, config file naming, and service identifiers.
	// If empty, defaults to CommitteeName.
	Name string `toml:"name"`
	// HostPort is the port on the host machine that the aggregator will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
	// ExposedHostPort is the port on the host machine that the gRPC server will be exposed on.
	// If set, the gRPC port (50051) will be directly accessible on localhost.
	// This is useful for testing without going through the nginx TLS proxy.
	ExposedHostPort int                       `toml:"grpc_host_port"`
	SourceCodePath  string                    `toml:"source_code_path"`
	RootPath        string                    `toml:"root_path"`
	DB              *AggregatorDBInput        `toml:"db"`
	Redis           *AggregatorRedisInput     `toml:"redis"`
	Out             *AggregatorOutput         `toml:"out"`
	Env             *AggregatorEnvConfig      `toml:"env"`
	APIClients      []*AggregatorClientConfig `toml:"api_clients"`
	CommitteeName   string                    `toml:"committee_name"`
	// Maps to Monitoring.Beholder.OtelExporterHTTPEndpoint in the aggregator config toml.
	MonitoringOtelExporterHTTPEndpoint string `toml:"monitoring_otel_exporter_http_endpoint"`

	// AggregationChannelBufferSize controls the size of the aggregation request channel buffer for individual client.
	// If 0, the default (10) is used. Useful for pentest scenarios to trigger channel exhaustion.
	AggregationChannelBufferSize int `toml:"aggregation_channel_buffer_size"`

	// BackgroundWorkerCount controls the number of aggregation workers.
	// If 0, the default (10) is used. Set to 1 for channel exhaustion tests.
	BackgroundWorkerCount int `toml:"background_worker_count"`

	// SharedTLSCerts contains shared TLS certificates for all aggregators.
	// If set, these certs will be used instead of generating new ones.
	SharedTLSCerts *TLSCertPaths `toml:"-"`

	// GeneratedCommittee is the pre-generated committee config from the deployments changesets.
	// This is set by environment.go after scanning on-chain state.
	GeneratedCommittee *model.Committee `toml:"-"`
}

type AggregatorOutput struct {
	UseCache           bool   `toml:"use_cache"`
	ContainerName      string `toml:"container_name"`
	Address            string `toml:"address"`
	ExternalHTTPUrl    string `toml:"external_http_url"`
	ExternalHTTPSUrl   string `toml:"external_https_url"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
	TLSCACertFile      string `toml:"tls_ca_cert_file"`
	// ClientCredentials maps ClientID to generated HMAC credentials.
	// Used by verifiers to automatically obtain their credentials.
	ClientCredentials map[string]hmacutil.Credentials `toml:"-"`
	// GeneratedCommittee is copied from AggregatorInput after config generation.
	// Saved here so tests can access it after loading from env-out.toml.
	GeneratedCommittee *model.Committee `toml:"generated_committee"`
}

func (o *AggregatorOutput) GetCredentialsForClient(clientID string) (hmacutil.Credentials, bool) {
	if o == nil || o.ClientCredentials == nil {
		return hmacutil.Credentials{}, false
	}
	creds, ok := o.ClientCredentials[clientID]
	return creds, ok
}

func (a *AggregatorInput) EnsureClientCredentials() (map[string]hmacutil.Credentials, error) {
	credentialsMap := make(map[string]hmacutil.Credentials)

	for _, client := range a.APIClients {
		if len(client.APIKeyPairs) == 0 {
			client.APIKeyPairs = []*AggregatorAPIKeyPair{{}}
		}

		for _, pair := range client.APIKeyPairs {
			if pair.APIKey == "" || pair.Secret == "" {
				creds, err := hmacutil.GenerateCredentials()
				if err != nil {
					return nil, fmt.Errorf("failed to generate credentials for client %s: %w", client.ClientID, err)
				}
				pair.APIKey = creds.APIKey
				pair.Secret = creds.Secret
			}
			credentialsMap[client.ClientID] = hmacutil.Credentials{
				APIKey: pair.APIKey,
				Secret: pair.Secret,
			}
		}
	}

	return credentialsMap, nil
}

// InstanceName returns the unique instance name for this aggregator.
// Falls back to CommitteeName when Name is not set.
func (a *AggregatorInput) InstanceName() string {
	if a.Name != "" {
		return a.Name
	}
	return a.CommitteeName
}

func validateAggregatorInput(in *AggregatorInput) error {
	if in.Image == "" {
		return fmt.Errorf("image is required for aggregator")
	}
	if in.HostPort == 0 {
		return fmt.Errorf("host port is required for aggregator")
	}
	if in.CommitteeName == "" {
		return fmt.Errorf("committee name is required for aggregator")
	}
	if in.SourceCodePath == "" {
		return fmt.Errorf("source code path is required for aggregator")
	}
	if in.RootPath == "" {
		return fmt.Errorf("root path is required for aggregator")
	}
	if in.DB == nil {
		return fmt.Errorf("explicit database configuration is required for aggregator")
	}
	if in.DB.HostPort == 0 || in.DB.Image == "" {
		return fmt.Errorf("invalid database configuration for aggregator, both of 'host_port' and 'image' must be set, got: %+v", in.DB)
	}
	if in.Redis == nil {
		return fmt.Errorf("explicit Redis configuration is required for aggregator")
	}
	if in.Redis.HostPort == 0 || in.Redis.Image == "" {
		return fmt.Errorf("invalid Redis configuration for aggregator, both of 'host_port' and 'image' must be set, got: %+v", in.Redis)
	}
	if in.Env == nil {
		return fmt.Errorf("explicit environment configuration is required for aggregator")
	}
	if in.Env.StorageConnectionURL == "" {
		return fmt.Errorf("storage connection URL is required for aggregator")
	}
	if in.Env.RedisAddress == "" {
		return fmt.Errorf("redis address is required for aggregator")
	}
	// Note: redis password can be empty.
	if in.Env.RedisDB == "" {
		return fmt.Errorf("redis DB is required for aggregator")
	}
	if in.GeneratedCommittee == nil {
		return fmt.Errorf("GeneratedCommittee is required - run config generation changeset first")
	}
	return nil
}

// GenerateConfigResult holds the output of GenerateConfigs.
type GenerateConfigResult struct {
	MainConfig      []byte
	GeneratedConfig []byte
}

// GenerateConfigs generates the aggregator service configuration using the inputs.
// It returns two TOML configs: the main config and the generated (committee) config.
// If GeneratedCommittee is set, it uses that instead of building from verifier inputs.
func (a *AggregatorInput) GenerateConfigs(generatedConfigFileName string) (*GenerateConfigResult, error) {
	if a.GeneratedCommittee == nil {
		return nil, fmt.Errorf("GeneratedCommittee is required - run config generation changeset first")
	}

	config, err := configuration.LoadConfigString(aggregatorConfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to load aggregator config template: %w", err)
	}

	// Use the pre-generated committee config from the changeset
	committeeConfig := a.GeneratedCommittee

	// Set the path to the generated config file (relative to main config)
	config.GeneratedConfigPath = generatedConfigFileName

	if a.MonitoringOtelExporterHTTPEndpoint != "" {
		config.Monitoring.Beholder.OtelExporterHTTPEndpoint = a.MonitoringOtelExporterHTTPEndpoint
	}

	// Override aggregation channel buffer size if specified (useful for pentest)
	if a.AggregationChannelBufferSize > 0 {
		config.Aggregation.ChannelBufferSize = a.AggregationChannelBufferSize
	}

	// Override background worker count if specified (useful for channel exhaustion tests)
	if a.BackgroundWorkerCount > 0 {
		config.Aggregation.BackgroundWorkerCount = a.BackgroundWorkerCount
	}

	for _, client := range a.APIClients {
		config.APIClients = append(config.APIClients, &model.ClientConfig{
			ClientID:    client.ClientID,
			Description: client.Description,
			Enabled:     client.Enabled,
			Groups:      client.Groups,
			APIKeyPairs: make([]*model.APIKeyPairEnv, 0, len(client.APIKeyPairs)),
		})
		for i := range client.APIKeyPairs {
			config.APIClients[len(config.APIClients)-1].APIKeyPairs = append(config.APIClients[len(config.APIClients)-1].APIKeyPairs, &model.APIKeyPairEnv{
				APIKeyEnvVar: fmt.Sprintf("AGGREGATOR_API_KEY_%s_%d", client.ClientID, i),
				SecretEnvVar: fmt.Sprintf("AGGREGATOR_SECRET_%s_%d", client.ClientID, i),
			})
		}
	}

	// Marshal main config (without committee - it's in the generated file)
	mainCfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal aggregator config to TOML: %w", err)
	}

	// Marshal generated config (committee only)
	generatedCfg := &model.GeneratedConfig{
		Committee: committeeConfig,
	}
	genCfgBytes, err := toml.Marshal(generatedCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal generated config to TOML: %w", err)
	}

	return &GenerateConfigResult{
		MainConfig:      mainCfg,
		GeneratedConfig: genCfgBytes,
	}, nil
}

func (a *AggregatorInput) GetAPIKeys() ([]AggregatorClientConfig, error) {
	apiKeyConfigs := make([]AggregatorClientConfig, 0, len(a.APIClients))
	for _, client := range a.APIClients {
		apiKeyConfigs = append(apiKeyConfigs, *client)
	}
	return apiKeyConfigs, nil
}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	if err := validateAggregatorInput(in); err != nil {
		return nil, err
	}

	clientCredentials, err := in.EnsureClientCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure client credentials: %w", err)
	}

	ctx := context.Background()
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	confDir := util.CCVConfigDir()
	instanceName := in.InstanceName()
	generatedConfigFileName := fmt.Sprintf("aggregator-%s-generated.toml", instanceName)
	configResult, err := in.GenerateConfigs(generatedConfigFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aggregator configs: %w", err)
	}

	configFilePath := filepath.Join(confDir,
		fmt.Sprintf("aggregator-%s-config.toml", instanceName))
	if err := os.WriteFile(configFilePath, configResult.MainConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write aggregator config to file: %w", err)
	}

	generatedConfigFilePath := filepath.Join(confDir, generatedConfigFileName)
	if err := os.WriteFile(generatedConfigFilePath, configResult.GeneratedConfig, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write aggregator generated config to file: %w", err)
	}

	aggregatorContainerName := fmt.Sprintf("%s-%s", instanceName, AggregatorContainerNameSuffix)
	nginxContainerName := fmt.Sprintf("%s-%s", instanceName, AggregatorNginxContainerNameSuffix)

	// Use shared TLS certs if provided, otherwise generate new ones
	tlsCerts := in.SharedTLSCerts
	if tlsCerts == nil {
		tlsCertDir := filepath.Join(confDir, fmt.Sprintf("tls-%s", instanceName))
		var err error
		tlsCerts, err = GenerateTLSCertificates([]string{
			nginxContainerName,
			aggregatorContainerName,
			"localhost",
		}, tlsCertDir)
		if err != nil {
			return nil, fmt.Errorf("failed to generate TLS certificates: %w", err)
		}
	}

	// Generate nginx configuration for gRPC TLS termination
	nginxConfPath := filepath.Join(confDir, fmt.Sprintf("nginx-%s.conf", instanceName))
	nginxConf := generateNginxConfig(aggregatorContainerName, DefaultAggregatorGRPCPort)
	if err := os.WriteFile(nginxConfPath, []byte(nginxConf), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write nginx config: %w", err)
	}

	// Start the aggregator postgres database container
	_, err = postgres.Run(ctx,
		in.DB.Image,
		// The container name should be scoped by the committee name.
		testcontainers.WithName(fmt.Sprintf("%s-%s", instanceName, AggregatorDBContainerNameSuffix)),
		// Database names don't have to be, its probably simpler we keep them the same across all containers
		// in case some debugging or some introspection is required.
		postgres.WithDatabase(DefaultAggregatorDBName),
		postgres.WithUsername(DefaultAggregatorDBUsername),
		postgres.WithPassword(DefaultAggregatorDBPassword),
		postgres.WithInitScripts(filepath.Join(p, DefaultAggregatorSQLInit)),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: fmt.Sprintf("%s-%s", instanceName, AggregatorDBContainerNameSuffix),
				// This is the container port, not the host port, so it can be the same across different containers.
				ExposedPorts: []string{DefaultDBContainerPort},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {fmt.Sprintf("%s-%s", instanceName, AggregatorDBContainerNameSuffix)},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = nat.PortMap{
						DefaultDBContainerPort: []nat.PortBinding{
							// The host port must be unique across all containers.
							{HostPort: strconv.Itoa(in.DB.HostPort)},
						},
					}
				},
				WaitingFor: wait.ForLog("database system is ready to accept connections"),
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Postgres container: %w", err)
	}

	// Start the aggregator redis container for rate limiting
	redisReq := testcontainers.ContainerRequest{
		Image: in.Redis.Image,
		Name:  fmt.Sprintf("%s-%s", instanceName, AggregatorRedisContainerNameSuffix),
		// This is the container port, not the host port, so it can be the same across different containers.
		ExposedPorts: []string{DefaultRedisContainerPort},
		Networks:     []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {fmt.Sprintf("%s-%s", instanceName, AggregatorRedisContainerNameSuffix)},
		},
		Labels: framework.DefaultTCLabels(),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				DefaultRedisContainerPort: []nat.PortBinding{
					// The host port must be unique across all containers.
					{HostPort: strconv.Itoa(in.Redis.HostPort)},
				},
			}
		},
		WaitingFor: wait.ForLog("Ready to accept connections"),
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis container: %w", err)
	}

	// Build environment variables from config
	envVars := make(map[string]string)

	if in.Env != nil {
		// Use explicit configuration from env.toml
		if in.Env.StorageConnectionURL == "" {
			return nil, fmt.Errorf("AGGREGATOR_STORAGE_CONNECTION_URL is required in env config")
		}
		envVars["AGGREGATOR_STORAGE_CONNECTION_URL"] = in.Env.StorageConnectionURL

		for _, client := range in.APIClients {
			for i, apiKeyPair := range client.APIKeyPairs {
				envVars[fmt.Sprintf("AGGREGATOR_API_KEY_%s_%d", client.ClientID, i)] = apiKeyPair.APIKey
				envVars[fmt.Sprintf("AGGREGATOR_SECRET_%s_%d", client.ClientID, i)] = apiKeyPair.Secret
			}
		}

		if in.Env.RedisAddress == "" {
			return nil, fmt.Errorf("AGGREGATOR_REDIS_ADDRESS is required in env config")
		}
		envVars["AGGREGATOR_REDIS_ADDRESS"] = in.Env.RedisAddress

		envVars["AGGREGATOR_REDIS_PASSWORD"] = in.Env.RedisPassword
		envVars["AGGREGATOR_REDIS_DB"] = in.Env.RedisDB
	}

	// Enable gRPC reflection in devenv for debugging
	envVars["AGGREGATOR_GRPC_REFLECTION_ENABLED"] = "true"

	// Start the aggregator container
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     aggregatorContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {aggregatorContainerName},
		},
		Env: envVars,
		// Aggregator listens on 50051 internally, nginx proxies TLS to it
		ExposedPorts: []string{"50051/tcp", "8080/tcp"},
		WaitingFor:   wait.ForHTTP("/health/live").WithPort("8080/tcp"),
	}

	// If ExposedHostPort is set, expose the gRPC port directly to the host
	if in.ExposedHostPort > 0 {
		req.HostConfigModifier = func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"50051/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.ExposedHostPort)},
				},
			}
		}
	}

	// Note: identical code to verifier.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		req.Files = []testcontainers.ContainerFile{
			{
				HostFilePath:      configFilePath,
				ContainerFilePath: aggregator.DefaultConfigFile,
				FileMode:          0o644,
			},
			{
				HostFilePath:      generatedConfigFilePath,
				ContainerFilePath: filepath.Join(filepath.Dir(aggregator.DefaultConfigFile), generatedConfigFileName),
				FileMode:          0o644,
			},
		}
		framework.L.Info().
			Str("Service", aggregatorContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	// Start the nginx TLS termination sidecar
	nginxReq := testcontainers.ContainerRequest{
		Image:    DefaultNginxImage,
		Name:     nginxContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {nginxContainerName},
		},
		ExposedPorts: []string{DefaultNginxTLSPort},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				DefaultNginxTLSPort: []nat.PortBinding{
					{HostPort: strconv.Itoa(in.HostPort)},
				},
			}
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      nginxConfPath,
				ContainerFilePath: "/etc/nginx/nginx.conf",
				FileMode:          0o644,
			},
			{
				HostFilePath:      tlsCerts.ServerCertFile,
				ContainerFilePath: "/etc/nginx/ssl/server.crt",
				FileMode:          0o644,
			},
			{
				HostFilePath:      tlsCerts.ServerKeyFile,
				ContainerFilePath: "/etc/nginx/ssl/server.key",
				FileMode:          0o600,
			},
		},
		WaitingFor: wait.ForListeningPort("443/tcp"),
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: nginxReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start nginx TLS proxy container: %w", err)
	}

	in.Out = &AggregatorOutput{
		ContainerName:      nginxContainerName,
		Address:            fmt.Sprintf("%s:443", nginxContainerName),
		ExternalHTTPUrl:    fmt.Sprintf("%s:%d", aggregatorContainerName, DefaultAggregatorGRPCPort),
		ExternalHTTPSUrl:   fmt.Sprintf("%s:%d", host, in.HostPort),
		TLSCACertFile:      tlsCerts.CACertFile,
		ClientCredentials:  clientCredentials,
		GeneratedCommittee: in.GeneratedCommittee,
	}
	return in.Out, nil
}

func generateNginxConfig(upstreamHost string, upstreamPort int) string {
	return fmt.Sprintf(`
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent"';
    access_log /var/log/nginx/access.log main;

    server {
        listen 443 ssl http2;

        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            grpc_pass grpc://%s:%d;
            error_page 502 = /error502grpc;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /error502grpc {
            internal;
            default_type application/grpc;
            add_header grpc-status 14;
            add_header grpc-message "unavailable";
            return 204;
        }
    }
}
`, upstreamHost, upstreamPort)
}
