package services

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	DefaultExecutorName  = "executor"
	DefaultExecutorImage = "executor:dev"
	DefaultExecutorPort  = 8101
	DefaultExecutorMode  = Standalone
)

//go:embed executor.template.toml
var executorConfigTemplate string

type ExecutorInput struct {
	Mode             Mode              `toml:"mode"`
	Out              *ExecutorOutput   `toml:"-"`
	Image            string            `toml:"image"`
	SourceCodePath   string            `toml:"source_code_path"`
	RootPath         string            `toml:"root_path"`
	ContainerName    string            `toml:"container_name"`
	Port             int               `toml:"port"`
	UseCache         bool              `toml:"use_cache"`
	OfframpAddresses map[uint64]string `toml:"offramp_addresses"`
	RmnAddresses     map[uint64]string `toml:"rmn_addresses"`
}

type ExecutorOutput struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPURL string `toml:"http_url"`
	InternalHTTPURL string `toml:"internal_http_url"`
	UseCache        bool   `toml:"use_cache"`
}

func (v *ExecutorInput) GenerateConfig() (executorTomlConfig []byte, err error) {
	var config executor.Configuration
	if _, err := toml.Decode(executorConfigTemplate, &config); err != nil {
		return nil, fmt.Errorf("failed to decode verifier config template: %w", err)
	}

	config.OffRampAddresses = make(map[string]string)
	for chainID, address := range v.OfframpAddresses {
		config.OffRampAddresses[strconv.FormatUint(chainID, 10)] = address
	}
	config.RmnAddresses = make(map[string]string)
	for chainID, address := range v.RmnAddresses {
		config.RmnAddresses[strconv.FormatUint(chainID, 10)] = address
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}

	return cfg, nil
}

func ApplyExecutorDefaults(in *ExecutorInput) {
	if in.Image == "" {
		in.Image = DefaultExecutorImage
	}
	if in.Port == 0 {
		in.Port = DefaultExecutorPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultExecutorName
	}
	if in.Mode == "" {
		in.Mode = DefaultExecutorMode
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
	ApplyExecutorDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Generate and store config file.
	config, err := in.GenerateConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for executor: %w", err)
	}
	confDir := util.CCVConfigDir()
	configFilePath := filepath.Join(confDir, "executor.toml")
	if err := os.WriteFile(configFilePath, config, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write executor config to file: %w", err)
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

	// Note: identical code to verifier.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		req.Mounts = append(req.Mounts, testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			configFilePath,
			executor.DefaultConfigFile,
		))
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

func ResolveContractsForExecutor(ds datastore.DataStore, blockchains []*blockchain.Input, exec *ExecutorInput) (*ExecutorInput, error) {
	exec.OfframpAddresses = make(map[uint64]string)
	exec.RmnAddresses = make(map[uint64]string)
	for _, chain := range blockchains {
		// TODO: Not chain agnostic.
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(chain.ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}

		offRampAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(offrampoperations.ContractType),
			semver.MustParse(offrampoperations.Deploy.Version()),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("failed to get off ramp address for chain %s: %w", chain.ChainID, err)
		}

		rmnRemoteAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			semver.MustParse(rmn_remote.Deploy.Version()),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("failed to get rmn remote address for chain %s: %w", chain.ChainID, err)
		}
		exec.OfframpAddresses[networkInfo.ChainSelector] = offRampAddressRef.Address
		exec.RmnAddresses[networkInfo.ChainSelector] = rmnRemoteAddressRef.Address
	}
	return exec, nil
}
