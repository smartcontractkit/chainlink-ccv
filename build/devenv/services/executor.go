package services

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	DefaultExecutorName  = "executor"
	DefaultExecutorID    = "cl_node_executor_a"
	DefaultExecutorImage = "executor:dev"
	DefaultExecutorPort  = 8101
	DefaultExecutorMode  = Standalone
	ExecutorIDPrefix     = "cl_node_executor_"
)

//go:embed executor.template.toml
var executorConfigTemplate string

type ExecutorInput struct {
	Mode              Mode              `toml:"mode"`
	Out               *ExecutorOutput   `toml:"-"`
	Image             string            `toml:"image"`
	SourceCodePath    string            `toml:"source_code_path"`
	RootPath          string            `toml:"root_path"`
	ContainerName     string            `toml:"container_name"`
	Port              int               `toml:"port"`
	UseCache          bool              `toml:"use_cache"`
	OfframpAddresses  map[uint64]string `toml:"offramp_addresses"`
	ExecutorPool      []string          `toml:"executor_pool"`
	ExecutorID        string            `toml:"executor_id"`
	RmnAddresses      map[uint64]string `toml:"rmn_addresses"`
	ExecutorAddresses map[uint64]string `toml:"executor_addresses"`
	IndexerAddress    string            `toml:"indexer_address"`

	// Only used in standalone mode.
	TransmitterPrivateKey string `toml:"transmitter_private_key"`
}

type ExecutorOutput struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPURL string `toml:"http_url"`
	InternalHTTPURL string `toml:"internal_http_url"`
	UseCache        bool   `toml:"use_cache"`
}

func (v *ExecutorInput) GenerateJobSpec() (executorJobSpec string, err error) {
	tomlConfigBytes, err := v.GenerateConfig()
	if err != nil {
		return "", fmt.Errorf("failed to generate executor config: %w", err)
	}
	return fmt.Sprintf(
		`
schemaVersion = 1
type = "ccvexecutor"
executorConfig = """
%s
"""
`, string(tomlConfigBytes),
	), nil
}

func (v *ExecutorInput) GenerateConfig() (executorTomlConfig []byte, err error) {
	var config executor.Configuration
	if _, err := toml.Decode(executorConfigTemplate, &config); err != nil {
		return nil, fmt.Errorf("failed to decode verifier config template: %w", err)
	}
	config.ChainConfiguration = make(map[string]executor.ChainConfiguration, len(v.OfframpAddresses))
	for chainSelector, address := range v.OfframpAddresses {
		if len(v.ExecutorPool) == 0 {
			return nil, errors.New("invalid ExecutorPool, should be non-empty")
		}
		if !slices.Contains(v.ExecutorPool, v.ExecutorID) {
			return nil, fmt.Errorf("invalid ExecutorID %s, should be in ExecutorPool %+v", v.ExecutorID, v.ExecutorPool)
		}
		config.ChainConfiguration[strconv.FormatUint(chainSelector, 10)] = executor.ChainConfiguration{
			OffRampAddress:         address,
			RmnAddress:             v.RmnAddresses[chainSelector],
			ExecutionInterval:      15 * time.Second,
			ExecutorPool:           v.ExecutorPool,
			DefaultExecutorAddress: v.ExecutorAddresses[chainSelector],
		}
	}

	if v.ExecutorID == "" {
		return nil, errors.New("invalid ExecutorID, should be non-empty")
	}
	if v.IndexerAddress != "" {
		// The default in the template is good for e2e tests on ephemeral envs.
		config.IndexerAddress = v.IndexerAddress
	}

	config.ExecutorID = v.ExecutorID

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}

	return cfg, nil
}

func (v *ExecutorInput) GetTransmitterAddress() protocol.UnknownAddress {
	// TODO: not chain agnostic.
	pk, err := crypto.HexToECDSA(v.TransmitterPrivateKey)
	if err != nil {
		return protocol.UnknownAddress{}
	}
	return protocol.UnknownAddress(crypto.PubkeyToAddress(pk.PublicKey).Bytes())
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
	configFilePath := filepath.Join(confDir, fmt.Sprintf("executor-%s-config.toml", in.ExecutorID))
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
			"EXECUTOR_TRANSMITTER_PRIVATE_KEY": in.TransmitterPrivateKey,
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

func generateTransmitterPrivateKey() (string, error) {
	// TODO: not chain agnostic.
	pk, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.FromECDSA(pk)), nil
}

// SetTransmitterPrivateKey sets the transmitter private key for the provided execs array.
func SetTransmitterPrivateKey(execs []*ExecutorInput) ([]*ExecutorInput, error) {
	for _, exec := range execs {
		pk, err := generateTransmitterPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate transmitter private key: %w", err)
		}
		exec.TransmitterPrivateKey = pk
	}
	return execs, nil
}

// SetExecutorPoolAndID sets the executor pool and ID for the provided execs array.
// The executor ID is set to the executor ID prefix followed by the index of the executor.
// The executor pool is set to the executor IDs.
func SetExecutorPoolAndID(execs []*ExecutorInput) ([]*ExecutorInput, error) {
	executorIDs := make([]string, 0, len(execs))
	for i := range execs {
		executorIDs = append(executorIDs, fmt.Sprintf("%s_%d", ExecutorIDPrefix, i))
	}

	for i, exec := range execs {
		exec.ExecutorID = executorIDs[i]
		exec.ExecutorPool = executorIDs
	}

	return execs, nil
}

// ResolveContractsForExecutor determines the offramp addresses for the executor and mutates the
// provided execs array to have the offramp addresses set.
func ResolveContractsForExecutor(ds datastore.DataStore, blockchains []*blockchain.Input, execs []*ExecutorInput) ([]*ExecutorInput, error) {
	for _, exec := range execs {
		exec.OfframpAddresses = make(map[uint64]string)
		exec.RmnAddresses = make(map[uint64]string)
		exec.ExecutorAddresses = make(map[uint64]string)
	}

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

		defaultExecutorAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(execcontract.ContractType),
			semver.MustParse(execcontract.Deploy.Version()),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("failed to get executor address for chain %s: %w", chain.ChainID, err)
		}

		for _, exec := range execs {
			exec.OfframpAddresses[networkInfo.ChainSelector] = offRampAddressRef.Address
			exec.RmnAddresses[networkInfo.ChainSelector] = rmnRemoteAddressRef.Address
			exec.ExecutorAddresses[networkInfo.ChainSelector] = defaultExecutorAddressRef.Address
		}
	}

	return execs, nil
}
