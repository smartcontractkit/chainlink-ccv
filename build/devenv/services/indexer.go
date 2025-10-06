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
	DefaultIndexerName     = "indexer"
	DefaultIndexerDBName   = "indexer-db"
	DefaultIndexerImage    = "indexer:dev"
	DefaultIndexerHTTPPort = 8102
	DefaultIndexerDBPort   = 6432
	DefaultIndexerSQLInit  = "init.sql"

	DefaultIndexerDBImage = "postgres:16-alpine"
)

var DefaultIndexerDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultIndexerName, DefaultIndexerName, DefaultIndexerDBPort, DefaultIndexerName)

type DBInput struct {
	Image string `toml:"image"`
}

type IndexerInput struct {
	Image          string         `toml:"image"`
	Port           int            `toml:"port"`
	SourceCodePath string         `toml:"source_code_path"`
	RootPath       string         `toml:"root_path"`
	DB             *DBInput       `toml:"db"`
	ContainerName  string         `toml:"container_name"`
	UseCache       bool           `toml:"use_cache"`
	Out            *IndexerOutput `toml:"-"`
	IndexerConfig  *config.Config `toml:"indexer_config"`
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
	if in.IndexerConfig == nil {
		in.IndexerConfig = &config.Config{
			Monitoring: config.MonitoringConfig{
				Enabled: true,
				Type:    "beholder",
				Beholder: config.BeholderConfig{
					InsecureConnection:       true,
					OtelExporterHTTPEndpoint: "otel-collector:4318",
					LogStreamingEnabled:      true,
					MetricReaderInterval:     5,
					TraceSampleRatio:         1.0,
					TraceBatchTimeout:        10,
				},
			},
			Scanner: config.ScannerConfig{
				ScanInterval:  1,
				ReaderTimeout: 5,
			},
			Discovery: config.DiscoveryConfig{
				Type: "static",
				Static: config.StaticDiscoveryConfig{
					Readers: []config.StaticDiscoveryReaderConfig{
						{
							Type: "aggregator",
							Aggregator: config.AggregatorReaderConfig{
								Address: "aggregator:50051",
								Since:   0,
							},
						},
					},
				},
			},
			Storage: config.StorageConfig{
				Type: "memory",
			},
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
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	configPath, ok := os.LookupEnv("INDEXER_CONFIG_PATH")
	if !ok {
		configPath = filepath.Join(p, "config.toml")
	}

	if _, err := os.Stat(configPath); err != nil {
		// Encode TOML to config file
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
		postgres.WithDatabase(DefaultIndexerName),
		postgres.WithUsername(DefaultIndexerName),
		postgres.WithPassword(DefaultIndexerName),
		postgres.WithInitScripts(filepath.Join(p, DefaultIndexerSQLInit)),
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

	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(p, in.RootPath, AppPathInsideContainer)...)
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

	return &IndexerOutput{
		ContainerName:      in.ContainerName,
		ExternalHTTPURL:    fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL:    fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
		DBConnectionString: DefaultIndexerDBConnectionString,
	}, nil
}
