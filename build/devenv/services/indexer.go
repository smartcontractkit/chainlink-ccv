package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	// DefaultIndexerName is the container name when exactly one indexer is used (legacy); prefer indexer-1 for consistency.
	DefaultIndexerName = "indexer"
	// FirstIndexerContainerName is the container name for the first indexer when using consistent naming (indexer-1, indexer-2, ...).
	FirstIndexerContainerName  = "indexer-1"
	DefaultIndexerDBName       = "indexer-db"
	IndexerDBContainerSuffix   = "-db"
	DefaultIndexerImage        = "indexer:latest"
	DefaultIndexerHTTPPort     = 8102
	DefaultIndexerInternalPort = 8100
	DefaultIndexerDBPort       = 6432

	DefaultIndexerDBImage = "postgres:16-alpine"

	// IndexerConfigDirContainer is the path inside the container where config files are mounted.
	IndexerConfigDirContainer = "/etc/ccv-indexer"
)

// DefaultIndexerDBConnectionString is the host-side connection string for the first indexer's DB (used by CLI db shell).
// Uses indexer-1 credentials so it works when exactly one indexer is configured (indexer-1).
var DefaultIndexerDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	FirstIndexerContainerName, FirstIndexerContainerName, DefaultIndexerDBPort, FirstIndexerContainerName)

type DBInput struct {
	Image    string `toml:"image"`
	HostPort int    `toml:"host_port"`
	// Database, Username, Password are optional. When empty, the service uses the indexer's container name
	// so each instance gets an isolated DB (required for multiple indexers).
	Database string `toml:"database"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type IndexerInput struct {
	// Version is the component config schema version (see indexer.Version).
	Version        int      `toml:"version"`
	Image          string   `toml:"image"`
	Port           int      `toml:"port"`
	SourceCodePath string   `toml:"source_code_path"`
	RootPath       string   `toml:"root_path"`
	DB             *DBInput `toml:"db"`
	ContainerName  string   `toml:"container_name"`
	// RedundantIndexers is the number of additional indexer instances to spawn
	// when Cfg.HighAvailability is true.
	// 0 = no redundancy (default), 1 = one extra (total 2), etc.
	RedundantIndexers int `toml:"redundant_indexers"`
	// Replicas is the number of indexer containers that share one DB behind an nginx proxy.
	// 0 or 1 runs a single container with no proxy.
	Replicas int `toml:"replicas"`
	// StorageConnectionURL is the full postgres connection string (container-to-container).
	// When set, used for injectPostgresURI and Out.DBConnectionString (aligned with aggregator.env.storage_connection_url).
	StorageConnectionURL             string                  `toml:"storage_connection_url"`
	UseCache                         bool                    `toml:"use_cache"`
	Out                              *IndexerOutput          `toml:"out"`
	IndexerConfig                    *config.Config          `toml:"indexer_config"`
	Secrets                          *config.SecretsConfig   `toml:"secrets"`
	GeneratedCfg                     *config.GeneratedConfig `toml:"generated_config"`
	CommitteeVerifierNameToQualifier map[string]string       `toml:"committee_verifier_name_to_qualifier"`
	CCTPVerifierNameToQualifier      map[string]string       `toml:"cctp_verifier_name_to_qualifier"`
	LombardVerifierNameToQualifier   map[string]string       `toml:"lombard_verifier_name_to_qualifier"`

	// TLSCACertFile is the path to the CA certificate file for TLS verification.
	// This is set by the aggregator service and used to trust the self-signed CA.
	TLSCACertFile string `toml:"-"`
}

type IndexerOutput struct {
	UseCache bool `toml:"use_cache"`
	// ContainerName is an indexer container (the first replica when Replicas > 1), for docker exec and kill tests.
	ContainerName string `toml:"container_name"`
	// ReplicaContainerNames lists all indexer containers; ProxyContainerName is the nginx proxy, empty for one replica.
	ReplicaContainerNames []string `toml:"replica_container_names"`
	ProxyContainerName    string   `toml:"proxy_container_name"`
	ExternalHTTPURL       string   `toml:"http_url"`
	InternalHTTPURL       string   `toml:"internal_http_url"`
	DBURL                 string   `toml:"db_url"`
	DBConnectionString    string   `toml:"db_connection_string"`
}

func defaults(in *IndexerInput) {
	if in.Image == "" {
		in.Image = DefaultIndexerImage
	}
	if in.Port == 0 {
		in.Port = DefaultIndexerHTTPPort
	}
	if in.ContainerName == "" {
		in.ContainerName = FirstIndexerContainerName
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image:    DefaultIndexerDBImage,
			HostPort: DefaultIndexerDBPort,
		}
	}
	if in.DB != nil && in.DB.HostPort == 0 {
		in.DB.HostPort = DefaultIndexerDBPort
	}
}

// injectPostgresURI sets the given URI on the single postgres storage backend in the config.
func injectPostgresURI(cfg *config.Config, uri string) {
	if cfg == nil || cfg.Storage.Single == nil || cfg.Storage.Single.Postgres == nil {
		return
	}
	cfg.Storage.Single.Postgres.URI = uri
}

// NewIndexer creates and starts a new Service container using testcontainers.
// Will be called once per indexer instance.
func NewIndexer(in *IndexerInput) (*IndexerOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()
	defaults(in)

	if in.GeneratedCfg == nil {
		return nil, fmt.Errorf("GeneratedCfg is required for indexer")
	}

	if in.IndexerConfig == nil {
		return nil, fmt.Errorf("IndexerConfig is required for indexer")
	}

	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Per-instance config dir and filenames (supports multiple indexers, like NewAggregator per committee).
	confDir := util.CCVConfigDir()
	configFileName := fmt.Sprintf("indexer-%s-config.toml", in.ContainerName)
	generatedConfigFileName := "generated.toml"
	secretsFileName := fmt.Sprintf("indexer-%s-secrets.toml", in.ContainerName)

	configPath := filepath.Join(confDir, configFileName)
	generatedConfigPath := filepath.Join(confDir, fmt.Sprintf("indexer-%s-generated.toml", in.ContainerName))
	secretsPath := filepath.Join(confDir, secretsFileName)

	in.IndexerConfig.GeneratedConfigPath = generatedConfigFileName

	// Per-instance DB credentials (from config or derived from container name for multi-instance isolation).
	dbName := in.DB.Database
	if dbName == "" {
		dbName = in.ContainerName
	}
	dbUser := in.DB.Username
	if dbUser == "" {
		dbUser = in.ContainerName
	}
	dbPass := in.DB.Password
	if dbPass == "" {
		dbPass = in.ContainerName
	}

	// DB connection string: from config (StorageConnectionURL) when set, else build from DB/container (aligned with aggregator).
	dbContainerName := in.ContainerName + IndexerDBContainerSuffix
	var dbConnectionString string
	if in.StorageConnectionURL != "" {
		dbConnectionString = in.StorageConnectionURL
	} else {
		dbConnectionString = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
			dbUser, dbPass, dbContainerName, dbName)
	}
	injectPostgresURI(in.IndexerConfig, dbConnectionString)

	buff := new(bytes.Buffer)
	encoder := toml.NewEncoder(buff)
	encoder.Indent = ""
	err = encoder.Encode(in.IndexerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode config: %w", err)
	}
	if err := os.WriteFile(configPath, buff.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	genBuff := new(bytes.Buffer)
	genEncoder := toml.NewEncoder(genBuff)
	genEncoder.Indent = ""
	if err := genEncoder.Encode(in.GeneratedCfg); err != nil {
		return nil, fmt.Errorf("failed to encode generated config: %w", err)
	}
	if err := os.WriteFile(generatedConfigPath, genBuff.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write generated config: %w", err)
	}

	secretsToEncode := in.Secrets
	if secretsToEncode == nil {
		secretsToEncode = &config.SecretsConfig{}
	}
	secretsBuffer := new(bytes.Buffer)
	secEncoder := toml.NewEncoder(secretsBuffer)
	secEncoder.Indent = ""
	if err := secEncoder.Encode(secretsToEncode); err != nil {
		return nil, fmt.Errorf("failed to encode secrets: %w", err)
	}
	if err := os.WriteFile(secretsPath, secretsBuffer.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write secrets file: %w", err)
	}

	// Database: unique name and host port per instance (like aggregator DB per committee).
	// one db instance per indexer.
	_, err = postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(dbContainerName),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) {
			h.ExtraHosts = append(h.ExtraHosts, HostGatewayExtraHost)
			h.PortBindings = network.PortMap{
				network.MustParsePort("5432/tcp"): []network.PortBinding{
					{HostPort: strconv.Itoa(in.DB.HostPort)},
				},
			}
		}),
		testcontainers.WithLabels(framework.DefaultTCLabels()),
		testcontainers.CustomizeRequestOption(func(req *testcontainers.GenericContainerRequest) error {
			req.Networks = []string{framework.DefaultNetworkName}
			req.NetworkAliases = map[string][]string{
				framework.DefaultNetworkName: {dbContainerName},
			}
			return nil
		}),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPass),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Internal API port: from indexer config or default (must match indexer binary ListenPort).
	internalPort := DefaultIndexerInternalPort
	if in.IndexerConfig != nil && in.IndexerConfig.API.ListenPort != 0 {
		internalPort = in.IndexerConfig.API.ListenPort
	}
	internalPortStr := strconv.Itoa(internalPort)

	files := indexerFiles{
		configPath:             configPath,
		generatedConfigPath:    generatedConfigPath,
		secretsPath:            secretsPath,
		containerConfigPath:    filepath.Join(IndexerConfigDirContainer, "config.toml"),
		containerGeneratedPath: filepath.Join(IndexerConfigDirContainer, generatedConfigFileName),
		containerSecretsPath:   filepath.Join(IndexerConfigDirContainer, "secrets.toml"),
	}
	if in.SourceCodePath != "" {
		framework.L.Info().Str("Service", in.ContainerName).Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	// One replica keeps the old layout. More replicas share the DB behind a proxy that takes
	// the indexer name and host port, so callers keep the same URLs.
	replicas := max(in.Replicas, 1)
	replicaNames := []string{in.ContainerName}
	proxyName := ""
	var front testcontainers.Container
	if replicas == 1 {
		front, err = startIndexerContainer(ctx, in, in.ContainerName, in.Port, internalPortStr, files)
		if err != nil {
			return nil, err
		}
	} else {
		replicaNames = make([]string, 0, replicas)
		for i := range replicas {
			name := fmt.Sprintf("%s-replica-%d", in.ContainerName, i+1)
			if _, err := startIndexerContainer(ctx, in, name, 0, internalPortStr, files); err != nil {
				return nil, err
			}
			replicaNames = append(replicaNames, name)
		}
		proxyName = in.ContainerName
		front, err = startIndexerProxy(ctx, proxyName, in.Port, internalPort, replicaNames, confDir)
		if err != nil {
			return nil, err
		}
	}
	host, err := front.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	out := &IndexerOutput{
		ContainerName:         replicaNames[0],
		ReplicaContainerNames: replicaNames,
		ProxyContainerName:    proxyName,
		ExternalHTTPURL:       fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL:       fmt.Sprintf("http://%s:%d", in.ContainerName, internalPort),
		DBURL:                 fmt.Sprintf("localhost:%d", in.DB.HostPort),
		DBConnectionString:    dbConnectionString,
	}
	in.Out = out
	return out, nil
}

// indexerFiles are the host config files and their paths inside an indexer container.
type indexerFiles struct {
	configPath, generatedConfigPath, secretsPath                      string
	containerConfigPath, containerGeneratedPath, containerSecretsPath string
}

// startIndexerContainer starts one indexer container; hostPort 0 publishes no host port.
func startIndexerContainer(ctx context.Context, in *IndexerInput, name string, hostPort int, internalPortStr string, f indexerFiles) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     name,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {name},
		},
		ExposedPorts: []string{internalPortStr + "/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.ExtraHosts = append(h.ExtraHosts, HostGatewayExtraHost)
			if hostPort != 0 {
				h.PortBindings = network.PortMap{
					network.MustParsePort(internalPortStr + "/tcp"): []network.PortBinding{
						{HostPort: strconv.Itoa(hostPort)},
					},
				}
			}
		},
		Env: map[string]string{
			"INDEXER_CONFIG_PATH":  f.containerConfigPath,
			"INDEXER_SECRETS_PATH": f.containerSecretsPath,
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: f.configPath, ContainerFilePath: f.containerConfigPath, FileMode: 0o644},
			{HostFilePath: f.generatedConfigPath, ContainerFilePath: f.containerGeneratedPath, FileMode: 0o644},
			{HostFilePath: f.secretsPath, ContainerFilePath: f.containerSecretsPath, FileMode: 0o644},
		},
	}

	if in.TLSCACertFile != "" {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			HostFilePath:      in.TLSCACertFile,
			ContainerFilePath: "/etc/ssl/certs/ca-certificates.crt",
			FileMode:          0o644,
		})
	}

	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start indexer container %q: %w", name, err)
	}
	return c, nil
}

// startIndexerProxy starts an nginx container that balances HTTP requests across the replicas.
func startIndexerProxy(ctx context.Context, name string, hostPort, listenPort int, replicas []string, confDir string) (testcontainers.Container, error) {
	confPath := filepath.Join(confDir, fmt.Sprintf("nginx-%s.conf", name))
	if err := os.WriteFile(confPath, []byte(generateIndexerProxyConfig(listenPort, replicas)), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write indexer proxy config: %w", err)
	}
	listenPortStr := strconv.Itoa(listenPort) + "/tcp"
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:    DefaultNginxImage,
			Name:     name,
			Labels:   framework.DefaultTCLabels(),
			Networks: []string{framework.DefaultNetworkName},
			NetworkAliases: map[string][]string{
				framework.DefaultNetworkName: {name},
			},
			ExposedPorts: []string{listenPortStr},
			HostConfigModifier: func(h *container.HostConfig) {
				h.PortBindings = network.PortMap{
					network.MustParsePort(listenPortStr): []network.PortBinding{{HostPort: strconv.Itoa(hostPort)}},
				}
			},
			Files: []testcontainers.ContainerFile{
				{HostFilePath: confPath, ContainerFilePath: "/etc/nginx/nginx.conf", FileMode: 0o644},
			},
		},
		Started: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start indexer proxy %q: %w", name, err)
	}
	return c, nil
}

// generateIndexerProxyConfig balances across replicas and retries the next one when a replica is down.
// "resolve" re-reads Docker DNS, so a restarted replica with a new IP is found again.
func generateIndexerProxyConfig(listenPort int, replicas []string) string {
	var servers strings.Builder
	for _, r := range replicas {
		fmt.Fprintf(&servers, "        server %s:%d resolve;\n", r, listenPort)
	}
	return fmt.Sprintf(`
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    access_log /var/log/nginx/access.log;
    resolver 127.0.0.11 valid=5s ipv6=off;

    upstream indexer {
        zone indexer 64k;
%s    }

    server {
        listen %d;

        location / {
            proxy_pass http://indexer;
            proxy_next_upstream error timeout http_502 http_503;
            proxy_connect_timeout 2s;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
`, servers.String(), listenPort)
}
