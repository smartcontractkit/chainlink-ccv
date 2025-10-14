package services

import (
	"context"
	"fmt"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultExecutorName  = "executor"
	DefaultExecutorImage = "executor:dev"
	DefaultExecutorPort  = 8101
)

type ExecutorInput struct {
	Out            *ExecutorOutput `toml:"-"`
	Image          string          `toml:"image"`
	SourceCodePath string          `toml:"source_code_path"`
	RootPath       string          `toml:"root_path"`
	ContainerName  string          `toml:"container_name"`
	Port           int             `toml:"port"`
	UseCache       bool            `toml:"use_cache"`
}

type ExecutorOutput struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPURL string `toml:"http_url"`
	InternalHTTPURL string `toml:"internal_http_url"`
	UseCache        bool   `toml:"use_cache"`
}

func executorDefaults(in *ExecutorInput) {
	if in.Image == "" {
		in.Image = DefaultExecutorImage
	}
	if in.Port == 0 {
		in.Port = DefaultExecutorPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultExecutorName
	}
}

func NewExecutor(in *ExecutorInput) (*ExecutorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()
	executorDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
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
		Env: map[string]string{
			"EXECUTOR_TRANSMITTER_PRIVATE_KEY": "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		},
	}

	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, GoSourcePathMounts(p, AppPathInsideContainer)...)
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
	in.Out = &ExecutorOutput{
		ContainerName:   in.ContainerName,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
	}
	return in.Out, nil
}
