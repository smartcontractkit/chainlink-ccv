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

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultIndexerName         = "indexer"
	DefaultIndexerDBName       = "indexer-db"
	DefaultIndexerImage        = "indexer:dev"
	DefaultIndexerHTTPPort     = 8102
	DefaultIndexerInternalPort = 8100
	DefaultIndexerDBPort       = 6432

	DefaultIndexerDBImage = "postgres:16-alpine"
)

var DefaultIndexerDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultIndexerName, DefaultIndexerName, DefaultIndexerDBPort, DefaultIndexerName)

type DBInput struct {
	Image string `toml:"image"`
}

type IndexerInput struct {
	Image                            string                  `toml:"image"`
	Port                             int                     `toml:"port"`
	SourceCodePath                   string                  `toml:"source_code_path"`
	RootPath                         string                  `toml:"root_path"`
	DB                               *DBInput                `toml:"db"`
	ContainerName                    string                  `toml:"container_name"`
	UseCache                         bool                    `toml:"use_cache"`
	Out                              *IndexerOutput          `toml:"out"`
	IndexerConfig                    *config.Config          `toml:"indexer_config"`
	Secrets                          *config.SecretsConfig   `toml:"secrets"`
	GeneratedCfg                     *config.GeneratedConfig `toml:"generated_config"`
	CommitteeVerifierNameToQualifier map[string]string       `toml:"committee_verifier_name_to_qualifier"`
	CCTPVerifierNameToQualifier      map[string]string       `toml:"cctp_verifier_name_to_qualifier"`

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
		in.ContainerName = DefaultIndexerName
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image: DefaultIndexerDBImage,
		}
	}
}

// NewIndexer creates and starts a new Service container using testcontainers.
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

	configPath, ok := os.LookupEnv("INDEXER_CONFIG_PATH")
	if !ok {
		configPath = filepath.Join(p, "config.toml")
	}

	generatedConfigFileName := "generated.toml"
	in.IndexerConfig.GeneratedConfigPath = generatedConfigFileName

	buff := new(bytes.Buffer)
	encoder := toml.NewEncoder(buff)
	encoder.Indent = ""
	err = encoder.Encode(in.IndexerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode config: %w", err)
	}

	err = os.WriteFile(configPath, buff.Bytes(), 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	// Write generated config file
	generatedConfigPath := filepath.Join(filepath.Dir(configPath), generatedConfigFileName)
	genBuff := new(bytes.Buffer)
	genEncoder := toml.NewEncoder(genBuff)
	genEncoder.Indent = ""
	err = genEncoder.Encode(in.GeneratedCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to encode generated config: %w", err)
	}
	err = os.WriteFile(generatedConfigPath, genBuff.Bytes(), 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to write generated config: %w", err)
	}

	secretsPath, ok := os.LookupEnv("INDEXER_SECRETS_PATH")
	if !ok {
		secretsPath = filepath.Join(p, "secrets.toml")
	}

	secretsBuffer := new(bytes.Buffer)
	secEncoder := toml.NewEncoder(secretsBuffer)
	secEncoder.Indent = ""
	err = secEncoder.Encode(in.Secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to encode secrets: %w", err)
	}

	err = os.WriteFile(secretsPath, secretsBuffer.Bytes(), 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to write secrets file: %w", err)
	}

	/* Database */

	_, err = postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(DefaultIndexerDBName),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"5432/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultIndexerDBPort)},
				},
			}
		}),
		testcontainers.WithLabels(framework.DefaultTCLabels()),
		testcontainers.CustomizeRequestOption(func(req *testcontainers.GenericContainerRequest) error {
			req.Networks = []string{framework.DefaultNetworkName}
			req.NetworkAliases = map[string][]string{
				framework.DefaultNetworkName: {DefaultIndexerDBName},
			}

			return nil
		}),
		postgres.WithDatabase(DefaultIndexerName),
		postgres.WithUsername(DefaultIndexerName),
		postgres.WithPassword(DefaultIndexerName),
		// Migrations are now handled by the application using goose
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
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
	}

	// Mount CA cert for TLS verification if provided. Only our self-signed CA is used for now.
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
		InternalHTTPURL:    fmt.Sprintf("http://%s:%d", in.ContainerName, DefaultIndexerInternalPort),
		DBConnectionString: DefaultIndexerDBConnectionString,
	}
	in.Out = out
	return out, nil
}
