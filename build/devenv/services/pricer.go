package services

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultPricerName  = "pricer"
	DefaultPricerImage = "pricer:dev"
	// default vars for a local devenv src chain: 1337.
	DefaultKeystoreAddress      = "0x9221E2E83903C731C2927CCd84e5fa02B22Bb1E2"
	DefaultKeystoreFilePath     = "../pricer/keystore.json"
	DefaultTestKeystorePassword = "keystore_test_password"
)

type KeystoreCfg struct {
	Address  string `toml:"address"`
	FilePath string `toml:"file_path"`
	Password string `toml:"password"`
}

type PricerInput struct {
	Image          string        `toml:"image"`
	SourceCodePath string        `toml:"source_code_path"`
	RootPath       string        `toml:"root_path"`
	ContainerName  string        `toml:"container_name"`
	UseCache       bool          `toml:"use_cache"`
	Keystore       *KeystoreCfg  `toml:"keystore"`
	Out            *PricerOutput `toml:"out"`
}

type PricerOutput struct {
	ContainerName string `toml:"container_name"`
}

func ApplyPricerDefaults(in *PricerInput) {
	if in.Image == "" {
		in.Image = DefaultPricerImage
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultPricerName
	}
	if in.Keystore == nil {
		in.Keystore = &KeystoreCfg{
			FilePath: DefaultKeystoreFilePath,
			Password: DefaultTestKeystorePassword,
			Address:  DefaultKeystoreAddress,
		}
	}
}

func NewPricer(in *PricerInput) (*PricerOutput, error) {
	ctx := context.Background()
	if in == nil {
		return nil, nil
	}
	if in.Out != nil {
		return in.Out, nil
	}
	ApplyPricerDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	keystoreData, err := os.ReadFile(filepath.Join(p, in.Keystore.FilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore")
	}
	keystoreBase64 := base64.StdEncoding.EncodeToString(keystoreData)

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
			"KEYSTORE_PASSWORD": in.Keystore.Password,
			"KEYSTORE_DATA":     keystoreBase64,
		},
	}

	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
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
	in.Out = &PricerOutput{
		ContainerName: in.ContainerName,
	}
	return in.Out, nil
}
