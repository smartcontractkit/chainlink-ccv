package services

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"
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

var (
	DefaultAggregatorDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
		DefaultAggregatorName, DefaultAggregatorName, DefaultAggregatorDBPort, DefaultAggregatorName)
)

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
	OfframpAddress string   `toml:"offrampAddress"`
	OnrampAddress  string   `toml:"onrampAddress"`
	Signers        []Signer `toml:"signers"`
	Threshold      uint8    `toml:"threshold"`
}

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs map[string]*QuorumConfig `toml:"quorumConfigs"`
}

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType string `toml:"type"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

// AggregatorConfig is the root configuration for the aggregator.
type AggregatorConfig struct {
	Server     ServerConfig          `toml:"server"`
	Storage    StorageConfig         `toml:"storage"`
	StubMode   bool                  `toml:"stubQuorumValidation"`
	Committees map[string]*Committee `toml:"committees"`
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
	if in.AggregatorConfig == nil {
		in.AggregatorConfig = &AggregatorConfig{
			Server: ServerConfig{
				Address: ":50051",
			},
			Storage: StorageConfig{
				StorageType: "memory",
			},
			Committees: map[string]*Committee{
				"default": {
					QuorumConfigs: map[string]*QuorumConfig{
						"1337": {
							OfframpAddress: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
							Signers: []Signer{
								{ParticipantID: "participant1", Addresses: []string{"0xffb9f9a3ae881f4b30e791d9e63e57a0e1facd66", "0x556bed6675c5d8a948d4d42bbf68c6da6c8968e3"}},
							},
							Threshold: 2,
						},
						"2337": {
							OfframpAddress: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
							Signers: []Signer{
								{ParticipantID: "participant1", Addresses: []string{"0xffb9f9a3ae881f4b30e791d9e63e57a0e1facd66"}},
								{ParticipantID: "participant2", Addresses: []string{"0x556bed6675c5d8a948d4d42bbf68c6da6c8968e3"}},
							},
							Threshold: 2,
						},
						"12922642891491394802": {
							OfframpAddress: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
							OnrampAddress:  "0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1",
							Signers: []Signer{
								{ParticipantID: "participant1", Addresses: []string{"0xffb9f9a3ae881f4b30e791d9e63e57a0e1facd66"}},
								{ParticipantID: "participant2", Addresses: []string{"0x556bed6675c5d8a948d4d42bbf68c6da6c8968e3"}},
							},
							Threshold: 2,
						},
						"3379446385462418246": {
							OfframpAddress: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
							OnrampAddress:  "0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1",
							Signers: []Signer{
								{ParticipantID: "participant1", Addresses: []string{"0xffb9f9a3ae881f4b30e791d9e63e57a0e1facd66"}},
								{ParticipantID: "participant2", Addresses: []string{"0x556bed6675c5d8a948d4d42bbf68c6da6c8968e3"}},
							},
							Threshold: 2,
						},
					},
				},
			},
		}
	}
}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
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
		testcontainers.WithName(DefaultAggregatorDBName),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"5432/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultAggregatorDBPort)},
				},
			}
		}),
		testcontainers.WithLabels(framework.DefaultTCLabels()),
		postgres.WithDatabase(DefaultAggregatorName),
		postgres.WithUsername(DefaultAggregatorName),
		postgres.WithPassword(DefaultAggregatorName),
		postgres.WithInitScripts(filepath.Join(p, DefaultAggregatorSQLInit)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	var aggreagtorConfigBuf bytes.Buffer
	if err := toml.NewEncoder(&aggreagtorConfigBuf).Encode(in.AggregatorConfig); err != nil {
		return nil, fmt.Errorf("failed to encode aggregator config: %w", err)
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
		Files: []testcontainers.ContainerFile{
			{
				Reader:            bytes.NewReader(aggreagtorConfigBuf.Bytes()),
				ContainerFilePath: "/app/aggregator.toml",
				FileMode:          0o644,
			},
		},
	}

	if in.SourceCodePath != "" {
		req.Mounts = GoSourcePathMounts(p, in.RootPath, AppPathInsideContainer)
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

	return &AggregatorOutput{
		ContainerName:      in.ContainerName,
		Address:            fmt.Sprintf("%s:%d", in.ContainerName, in.Port),
		DBConnectionString: DefaultAggregatorDBConnectionString,
	}, nil
}
