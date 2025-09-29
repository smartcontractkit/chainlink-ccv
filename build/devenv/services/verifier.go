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

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	commontypes "github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
)

const (
	DefaultVerifierName    = "verifier"
	DefaultVerifierDBName  = "verifier-db"
	DefaultVerifierImage   = "verifier:dev"
	DefaultVerifierPort    = 8100
	DefaultVerifierDBPort  = 8432
	DefaultVerifierSQLInit = "init.sql"

	DefaultVerifierDBImage = "postgres:16-alpine"
)

var DefaultVerifierDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultVerifierName, DefaultVerifierName, DefaultVerifierDBPort, DefaultVerifierName)

// ConvertBlockchainOutputsToInfo converts blockchain.Output to BlockchainInfo.
func ConvertBlockchainOutputsToInfo(outputs []*blockchain.Output) map[string]*protocol.BlockchainInfo {
	infos := make(map[string]*protocol.BlockchainInfo)
	for _, output := range outputs {
		info := &protocol.BlockchainInfo{
			ChainID:       output.ChainID,
			Type:          output.Type,
			Family:        output.Family,
			ContainerName: output.ContainerName,
			Nodes:         make([]*protocol.Node, 0, len(output.Nodes)),
		}

		// Convert all nodes
		for _, node := range output.Nodes {
			if node != nil {
				convertedNode := &protocol.Node{
					ExternalHTTPUrl: node.ExternalHTTPUrl,
					InternalHTTPUrl: node.InternalHTTPUrl,
					ExternalWSUrl:   node.ExternalWSUrl,
					InternalWSUrl:   node.InternalWSUrl,
				}
				info.Nodes = append(info.Nodes, convertedNode)
			}
		}

		infos[output.ChainID] = info
	}
	return infos
}

type VerifierDBInput struct {
	Image string `toml:"image"`
	Name  string `toml:"name"`
	Port  int    `toml:"port"`
}

type VerifierInput struct {
	DB                *VerifierDBInput           `toml:"db"`
	Out               *VerifierOutput            `toml:"out"`
	Image             string                     `toml:"image"`
	SourceCodePath    string                     `toml:"source_code_path"`
	RootPath          string                     `toml:"root_path"`
	ContainerName     string                     `toml:"container_name"`
	VerifierConfig    commontypes.VerifierConfig `toml:"verifier_config"`
	Port              int                        `toml:"port"`
	UseCache          bool                       `toml:"use_cache"`
	ConfigFilePath    string                     `toml:"config_file_path"`
	BlockchainOutputs []*blockchain.Output       `toml:"-"`
	AggregatorAddress string                     `toml:"aggregator_address"`
}

type VerifierOutput struct {
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
	UseCache           bool   `toml:"use_cache"`
}

func verifierDefaults(in *VerifierInput) {
	if in.Image == "" {
		in.Image = DefaultVerifierImage
	}
	if in.Port == 0 {
		in.Port = DefaultVerifierPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultVerifierName
	}
	if in.DB == nil {
		in.DB = &VerifierDBInput{
			Image: DefaultVerifierDBImage,
			Name:  DefaultVerifierDBName,
			Port:  DefaultVerifierDBPort,
		}
	}
	if in.ConfigFilePath == "" {
		in.ConfigFilePath = "/app/verifier-1.toml"
	}
}

func NewVerifier(in *VerifierInput) (*VerifierOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	verifierDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	/* Database */
	_, err = postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(in.DB.Name),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"5432/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.DB.Port)},
				},
			}
		}),
		testcontainers.WithLabels(framework.DefaultTCLabels()),
		postgres.WithDatabase(DefaultVerifierName),
		postgres.WithUsername(DefaultVerifierName),
		postgres.WithPassword(DefaultVerifierName),
		postgres.WithInitScripts(filepath.Join(p, DefaultVerifierSQLInit)),
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
		Env: map[string]string{
			"VERIFIER_CONFIG_PATH": in.ConfigFilePath,
		},
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

	return &VerifierOutput{
		ContainerName:      in.ContainerName,
		ExternalHTTPURL:    fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL:    fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
		DBConnectionString: DefaultVerifierDBConnectionString,
	}, nil
}
