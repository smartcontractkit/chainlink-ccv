package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
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
	DefaultIndexerImage        = "indexer:dev"
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
	Image          string   `toml:"image"`
	Port           int      `toml:"port"`
	SourceCodePath string   `toml:"source_code_path"`
	RootPath       string   `toml:"root_path"`
	DB             *DBInput `toml:"db"`
	ContainerName  string   `toml:"container_name"`
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
	UseCache           bool   `toml:"use_cache"`
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
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
			h.PortBindings = nat.PortMap{
				"5432/tcp": []nat.PortBinding{
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

	// Container paths for mounted config (same path in every container; each has its own files).
	containerConfigPath := filepath.Join(IndexerConfigDirContainer, "config.toml")
	containerGeneratedPath := filepath.Join(IndexerConfigDirContainer, generatedConfigFileName)
	containerSecretsPath := filepath.Join(IndexerConfigDirContainer, "secrets.toml")

	/* Service */
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		ExposedPorts: []string{internalPortStr + "/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				nat.Port(internalPortStr + "/tcp"): []nat.PortBinding{
					{HostPort: strconv.Itoa(in.Port)},
				},
			}
		},
		Env: map[string]string{
			"INDEXER_CONFIG_PATH":  containerConfigPath,
			"INDEXER_SECRETS_PATH": containerSecretsPath,
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: configPath, ContainerFilePath: containerConfigPath, FileMode: 0o644},
			{HostFilePath: generatedConfigPath, ContainerFilePath: containerGeneratedPath, FileMode: 0o644},
			{HostFilePath: secretsPath, ContainerFilePath: containerSecretsPath, FileMode: 0o644},
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
		framework.L.Info().
			Str("Service", in.ContainerName).
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

	out := &IndexerOutput{
		ContainerName:      in.ContainerName,
		ExternalHTTPURL:    fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL:    fmt.Sprintf("http://%s:%d", in.ContainerName, internalPort),
		DBURL:              fmt.Sprintf("localhost:%d", in.DB.HostPort),
		DBConnectionString: dbConnectionString,
	}
	in.Out = out
	return out, nil
}
