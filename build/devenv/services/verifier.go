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

// Node represents a blockchain node with connection information
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"`
}

// BlockchainInfo represents simplified blockchain information for the verifier
type BlockchainInfo struct {
	ChainID       string  `json:"chain_id"`
	Type          string  `json:"type"`
	Family        string  `json:"family"`
	ContainerName string  `json:"container_name"`
	Nodes         []*Node `json:"nodes"`
}

// ConvertBlockchainOutputsToInfo converts blockchain.Output to BlockchainInfo
func ConvertBlockchainOutputsToInfo(outputs []*blockchain.Output) map[string]*BlockchainInfo {
	infos := make(map[string]*BlockchainInfo)
	for _, output := range outputs {
		info := &BlockchainInfo{
			ChainID:       output.ChainID,
			Type:          output.Type,
			Family:        output.Family,
			ContainerName: output.ContainerName,
			Nodes:         make([]*Node, 0, len(output.Nodes)),
		}

		// Convert all nodes
		for _, node := range output.Nodes {
			if node != nil {
				convertedNode := &Node{
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
}

type VerifierConfig struct {
	AggregatorAddress string `toml:"aggregator_address"`
}

type VerifierInput struct {
	DB                *DBInput             `toml:"db"`
	Out               *VerifierOutput      `toml:"out"`
	Image             string               `toml:"image"`
	SourceCodePath    string               `toml:"source_code_path"`
	ContainerName     string               `toml:"container_name"`
	VerifierConfig    VerifierConfig       `toml:"verifier_config"`
	Port              int                  `toml:"port"`
	UseCache          bool                 `toml:"use_cache"`
	BlockchainOutputs []*blockchain.Output `toml:"-"`
}

type VerifierOutput struct {
	ContainerName      string                     `toml:"container_name"`
	ExternalHTTPURL    string                     `toml:"http_url"`
	InternalHTTPURL    string                     `toml:"internal_http_url"`
	DBURL              string                     `toml:"db_url"`
	DBConnectionString string                     `toml:"db_connection_string"`
	UseCache           bool                       `toml:"use_cache"`
	BlockchainInfos    map[string]*BlockchainInfo `toml:"-"`
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
		in.DB = &DBInput{
			Image: DefaultVerifierDBImage,
		}
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
		testcontainers.WithName(DefaultVerifierDBName),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"5432/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultVerifierDBPort)},
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
				ContainerFilePath: "/app/verifier.toml",
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
	var blockchainInfos map[string]*BlockchainInfo
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
