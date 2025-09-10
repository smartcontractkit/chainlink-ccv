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
func ConvertBlockchainOutputsToInfo(outputs []*blockchain.Output) map[string]*commontypes.BlockchainInfo {
	infos := make(map[string]*commontypes.BlockchainInfo)
	for _, output := range outputs {
		info := &commontypes.BlockchainInfo{
			ChainID:       output.ChainID,
			Type:          output.Type,
			Family:        output.Family,
			ContainerName: output.ContainerName,
			Nodes:         make([]*commontypes.Node, 0, len(output.Nodes)),
		}

		// Convert all nodes
		for _, node := range output.Nodes {
			if node != nil {
				convertedNode := &commontypes.Node{
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

type VerifierConfig struct {
	AggregatorAddress string                                 `toml:"aggregator_address"`
	PrivateKey        string                                 `toml:"private_key"`
	BlockchainInfos   map[string]*commontypes.BlockchainInfo `toml:"blockchain_infos"`
	CCVProxy1337      string                                 `toml:"ccv_proxy_1337"`
	CCVProxy2337      string                                 `toml:"ccv_proxy_2337"`
}

type VerifierInput struct {
	DB                *VerifierDBInput     `toml:"db"`
	Out               *VerifierOutput      `toml:"out"`
	Image             string               `toml:"image"`
	SourceCodePath    string               `toml:"source_code_path"`
	ContainerName     string               `toml:"container_name"`
	VerifierConfig    VerifierConfig       `toml:"verifier_config"`
	Port              int                  `toml:"port"`
	UseCache          bool                 `toml:"use_cache"`
	ConfigFilePath    string               `toml:"config_file_path"`
	BlockchainOutputs []*blockchain.Output `toml:"-"`
	AggregatorAddress string               `toml:"aggregator_address"`
}

type VerifierOutput struct {
	BlockchainInfos    map[string]*commontypes.BlockchainInfo `toml:"-"`
	ContainerName      string                                 `toml:"container_name"`
	ExternalHTTPURL    string                                 `toml:"http_url"`
	InternalHTTPURL    string                                 `toml:"internal_http_url"`
	DBURL              string                                 `toml:"db_url"`
	DBConnectionString string                                 `toml:"db_connection_string"`
	UseCache           bool                                   `toml:"use_cache"`
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
		in.ConfigFilePath = "/app/verifier.toml"
	}
}

func NewVerifier(in *VerifierInput) (*VerifierOutput, error) {
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

	var verifierConfigBuf bytes.Buffer
	if err := toml.NewEncoder(&verifierConfigBuf).Encode(in.VerifierConfig); err != nil {
		return nil, fmt.Errorf("failed to encode verifier config: %w", err)
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
			"VERIFIER_CONFIG": in.ConfigFilePath,
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
		Files: []testcontainers.ContainerFile{
			{
				Reader:            bytes.NewReader(verifierConfigBuf.Bytes()),
				ContainerFilePath: in.ConfigFilePath,
				FileMode:          0o644,
			},
		},
	}

	if in.SourceCodePath != "" {
		//nolint:staticcheck // ignore for now
		req.Mounts = testcontainers.Mounts(
			testcontainers.BindMount(
				p,
				AppPathInsideContainer,
			),
			testcontainers.BindMount(
				filepath.Join(p, "../protocol"),
				"/protocol",
			),
			testcontainers.VolumeMount(
				"go-mod-cache",
				"/go/pkg/mod",
			),
			testcontainers.VolumeMount(
				"go-build-cache",
				"/root/.cache/go-build",
			),
		)
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

	// Convert blockchain outputs to simplified format
	var blockchainInfos map[string]*commontypes.BlockchainInfo
	if in.BlockchainOutputs != nil {
		blockchainInfos = ConvertBlockchainOutputsToInfo(in.BlockchainOutputs)
	}

	return &VerifierOutput{
		ContainerName:      in.ContainerName,
		ExternalHTTPURL:    fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL:    fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
		DBConnectionString: DefaultVerifierDBConnectionString,
		BlockchainInfos:    blockchainInfos,
	}, nil
}
