package services

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultAggregatorName    = "aggregator"
	DefaultAggregatorDBName  = "aggregator-db"
	DefaultAggregatorImage   = "aggregator:dev"
	DefaultAggregatorPort    = 8103
	DefaultAggregatorDBPort  = 7432
	DefaultAggregatorSQLInit = "init.sql"

	DefaultAggregatorDBImage = "postgres:16-alpine"
)

var DefaultAggregatorDBConnectionString = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
	DefaultAggregatorName, DefaultAggregatorName, DefaultAggregatorDBName, DefaultAggregatorName)

type AggregatorDBInput struct {
	Image string `toml:"image"`
}

type AggregatorInput struct {
	Image            string            `toml:"image"`
	Port             int               `toml:"port"`
	SourceCodePath   string            `toml:"source_code_path"`
	RootPath         string            `toml:"root_path"`
	DB               *DBInput          `toml:"db"`
	ContainerName    string            `toml:"container_name"`
	UseCache         bool              `toml:"use_cache"`
	Out              *AggregatorOutput `toml:"-"`
	AggregatorConfig *AggregatorConfig `toml:"aggregator_config"`
}

type AggregatorOutput struct {
	UseCache           bool   `toml:"use_cache"`
	ContainerName      string `toml:"container_name"`
	Address            string `toml:"address"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
}

type Signer struct {
	ParticipantID string   `toml:"participantID"`
	Addresses     []string `toml:"addresses"`
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	CommitteeVerifierAddress string   `toml:"committeeVerifierAddress"`
	Signers                  []Signer `toml:"signers"`
	Threshold                uint8    `toml:"threshold"`
}

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs           map[string]*QuorumConfig `toml:"quorumConfigs"`
	SourceVerifierAddresses map[string]string        `toml:"sourceVerifierAddresses"`
}

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType   string `toml:"type"`
	ConnectionURL string `toml:"connectionURL,omitempty"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

// BeholderConfig wraps the beholder configuration to expose a minimal config for the aggregator.
type BeholderConfig struct {
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `toml:"insecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `toml:"caCertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `toml:"otelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `toml:"otelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `toml:"logStreamingEnabled"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `toml:"metricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `toml:"traceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `toml:"traceBatchTimeout"`
}

// MonitoringConfig provides all configuration for the monitoring system inside the aggregator.
type MonitoringConfig struct {
	// Enabled enables the monitoring system.
	Enabled bool `toml:"enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `toml:"type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `toml:"beholder"`
}

// AggregatorConfig is the root configuration for the aggregator.
type AggregatorConfig struct {
	Server     ServerConfig          `toml:"server"`
	Storage    StorageConfig         `toml:"storage"`
	StubMode   bool                  `toml:"stubQuorumValidation"`
	Committees map[string]*Committee `toml:"committees"`
	Monitoring MonitoringConfig      `toml:"monitoring"`
}

func aggregatorDefaults(in *AggregatorInput) {
	if in.Image == "" {
		in.Image = DefaultAggregatorImage
	}
	if in.Port == 0 {
		in.Port = DefaultAggregatorPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultAggregatorName
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image: DefaultAggregatorDBImage,
		}
	}

}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()
	aggregatorDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	/* Database */
	_, err = postgres.Run(ctx,
		in.DB.Image,
		postgres.WithDatabase(DefaultAggregatorName),
		postgres.WithUsername(DefaultAggregatorName),
		postgres.WithPassword(DefaultAggregatorName),
		postgres.WithInitScripts(filepath.Join(p, DefaultAggregatorSQLInit)),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name:         DefaultAggregatorDBName,
				ExposedPorts: []string{"5432/tcp"},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {DefaultAggregatorDBName},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = nat.PortMap{
						"5432/tcp": []nat.PortBinding{
							{HostPort: strconv.Itoa(DefaultAggregatorDBPort)},
						},
					}
				},
			},
		}),
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
		ExposedPorts: []string{"50051/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				"50051/tcp": []nat.PortBinding{
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

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}
	in.Out = &AggregatorOutput{
		ContainerName:      in.ContainerName,
		Address:            fmt.Sprintf("%s:%d", in.ContainerName, in.Port),
		DBConnectionString: DefaultAggregatorDBConnectionString,
	}
	return in.Out, nil
}
