package kmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	DefaultKMDImage         = "kmd:dev"
	DefaultKMDContainerName = "kmd"
	DefaultKeystoreFilePath = "/etc/kmd/keystore.json"
	DefaultKeystorePassword = "keystore_test_password"
	DefaultKMDContainerPort = "7788"
)

type KeystoreConfig struct {
	// FilePath is the path to the keystore file in the container.
	FilePath string `toml:"file_path"`

	// Password is the password used to encrypt/decrypt the keystore.
	Password string `toml:"password"`
}

type KMDInput struct {
	Image         string `toml:"image"`
	ContainerName string `toml:"container_name"`
	// HostPort is the port on the host machine that the KMD server will be exposed on.
	// This should be unique across all containers.
	HostPort       int             `toml:"host_port"`
	KeystoreConfig *KeystoreConfig `toml:"keystore_config"`
	Out            *KMDOutput      `toml:"out"`
}

type KMDOutput struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPUrl string `toml:"external_http_url"`
	InternalHTTPUrl string `toml:"internal_http_url"`
}

type DBInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the database will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
}

func ApplyPricerDefaults(in *KMDInput) {
	if in.Image == "" {
		in.Image = DefaultKMDImage
	}
	if in.KeystoreConfig == nil {
		in.KeystoreConfig = &KeystoreConfig{
			FilePath: DefaultKeystoreFilePath,
			Password: DefaultKeystorePassword,
		}
	}
}

func New(in *KMDInput) (*KMDOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil {
		return in.Out, nil
	}
	ApplyPricerDefaults(in)

	tempDir, err := os.MkdirTemp(os.TempDir(), "kmd-keystore-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		// This is the container port, not the host port, so it can be the same across different containers.
		ExposedPorts: []string{fmt.Sprintf("%s/tcp", DefaultKMDContainerPort)},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				nat.Port(fmt.Sprintf("%s/tcp", DefaultKMDContainerPort)): []nat.PortBinding{
					// The host port must be unique across all containers.
					{HostPort: strconv.Itoa(in.HostPort)},
				},
			}
		},
		Env: map[string]string{
			"KEYSTORE_PASSWORD":  in.KeystoreConfig.Password,
			"KEYSTORE_FILE_PATH": in.KeystoreConfig.FilePath,
			"KMD_PORT":           DefaultKMDContainerPort,
		},
		Mounts: testcontainers.ContainerMounts{
			{
				// Source should be a directory.
				Source: testcontainers.GenericBindMountSource{
					HostPath: tempDir,
				},
				// Target should be a directory.
				Target: testcontainers.ContainerMountTarget(filepath.Dir(in.KeystoreConfig.FilePath)),
			},
		},
		WaitingFor: wait.ForHTTP("/health"),
	}

	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start KMD container: %w", err)
	}
	host, err := c.Host(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get KMD container host: %w", err)
	}

	in.Out = &KMDOutput{
		ContainerName:   in.ContainerName,
		ExternalHTTPUrl: fmt.Sprintf("http://%s:%d", host, in.HostPort),
		InternalHTTPUrl: fmt.Sprintf("http://%s:%d", in.ContainerName, DefaultKMDContainerPort),
	}

	return in.Out, nil
}
