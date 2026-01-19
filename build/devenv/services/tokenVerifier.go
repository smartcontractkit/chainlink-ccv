package services

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

//go:embed tokenVerifier.template.toml
var tokenVerifierConfigTemplate string

type TokenVerifierInput struct {
	Mode           Mode                 `toml:"mode"`
	Out            *TokenVerifierOutput `toml:"-"`
	Image          string               `toml:"image"`
	SourceCodePath string               `toml:"source_code_path"`
	RootPath       string               `toml:"root_path"`
	ContainerName  string               `toml:"container_name"`
	Port           int                  `toml:"port"`

	// Maps to on_ramp_addresses in the verifier config toml.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// Maps to committee_verifier_addresses in the verifier config toml.
	DefaultExecutorOnRampAddresses map[string]string `toml:"default_executor_on_ramp_addresses"`
	// Maps to rmn_remote_addresses in the verifier config toml.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`

	CCTPVerifierAddresses map[string]string `toml:"cctp_verifier_addresses"`
}

type TokenVerifierOutput struct {
	ContainerName   string `toml:"container_name"`
	ExternalHTTPURL string `toml:"http_url"`
	InternalHTTPURL string `toml:"internal_http_url"`
	UseCache        bool   `toml:"use_cache"`
}

func NewTokenVerifier(in *TokenVerifierInput) (*TokenVerifierOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()

	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Generate blockchain infos for standalone mode
	blockchainInfos, err := GetBlockchainInfoFromTemplate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate blockchain infos: %w", err)
	}

	// Generate and store config file.
	config, err := in.GenerateConfigWithBlockchainInfos(blockchainInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for token verifier %w", err)
	}

	confDir := util.CCVConfigDir()
	configFilePath := filepath.Join(confDir, "verifier-config.toml")
	if err := os.WriteFile(configFilePath, config, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write aggregator config to file: %w", err)
	}

	envVars := make(map[string]string)
	/* Service */
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		Env: envVars,
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
		WaitingFor: wait.ForLog("Using real blockchain information from environment").
			WithStartupTimeout(120 * time.Second).
			WithPollInterval(3 * time.Second),
	}

	// Note: identical code to aggregator.go/executor.go -- will indexer be identical as well?
	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		req.Mounts = append(req.Mounts, testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			configFilePath,
			aggregator.DefaultConfigFile,
		))
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	const maxAttempts = 3
	var c testcontainers.Container
	var lastErr error

	// We need this retry loop because sometimes air will fail to start the server
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err == nil {
			break
		}

		lastErr = err
		framework.L.Warn().Err(err).Int("attempt", attempt).Msg("Container failed to start, retrying...")

		if c != nil {
			_ = c.Terminate(ctx)
		}

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to start container after %d attempts: %w", maxAttempts, lastErr)
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	return &TokenVerifierOutput{
		ContainerName:   in.ContainerName,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
	}, nil
}

func (v *TokenVerifierInput) GenerateConfigWithBlockchainInfos(blockchainInfos map[string]*protocol.BlockchainInfo) (verifierTomlConfig []byte, err error) {
	// Build base configuration
	var baseConfig token.Config
	if err := v.buildVerifierConfiguration(&baseConfig); err != nil {
		return nil, err
	}

	// Wrap in ConfigWithBlockchainInfo and add blockchain infos
	config := token.ConfigWithBlockchainInfos{
		Config:          baseConfig,
		BlockchainInfos: blockchainInfos,
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}
	return cfg, nil
}

func (v *TokenVerifierInput) buildVerifierConfiguration(config *token.Config) error {
	if _, err := toml.Decode(tokenVerifierConfigTemplate, &config); err != nil {
		return fmt.Errorf("failed to decode verifier config template: %w", err)
	}

	config.VerifierID = v.ContainerName
	config.OnRampAddresses = v.OnRampAddresses
	config.RMNRemoteAddresses = v.RMNRemoteAddresses
	if len(config.TokenVerifiers) == 0 {
		config.TokenVerifiers = make([]token.VerifierConfig, 0)
	}

	if len(v.CCTPVerifierAddresses) > 0 {
		verifiers := make(map[string]any)
		for k, addr := range v.CCTPVerifierAddresses {
			verifiers[k] = addr
		}
		config.TokenVerifiers = append(config.TokenVerifiers, token.VerifierConfig{
			Type:    "cctp",
			Version: "2.0",
			CCTPConfig: &cctp.CCTPConfig{
				AttestationAPI:         "http://fake:9111/cctp",
				AttestationAPIInterval: 100 * time.Millisecond,
				AttestationAPITimeout:  1 * time.Second,
				Verifiers:              verifiers,
			},
		})
	}

	return nil
}

func ResolveContractsForTokenVerifier(ds datastore.DataStore, blockchains []*blockchain.Input, ver TokenVerifierInput) (TokenVerifierInput, error) {
	ver.OnRampAddresses = make(map[string]string)
	ver.DefaultExecutorOnRampAddresses = make(map[string]string)
	ver.RMNRemoteAddresses = make(map[string]string)
	ver.CCTPVerifierAddresses = make(map[string]string)

	for _, chain := range blockchains {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(chain.ChainID, chainsel.FamilyEVM)
		if err != nil {
			return TokenVerifierInput{}, err
		}
		selectorStr := strconv.FormatUint(networkInfo.ChainSelector, 10)

		cctpTokenVerifierAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(cctp_verifier.ResolverType),
			semver.MustParse(cctp_verifier.Deploy.Version()),
			"CCTP",
		))
		if err != nil {
			framework.L.Info().
				Str("chainID", chain.ChainID).
				Msg("Failed to get CCTP Verifier address from datastore")
		} else {
			ver.CCTPVerifierAddresses[selectorStr] = cctpTokenVerifierAddressRef.Address
		}

		onRampAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(onrampoperations.ContractType),
			semver.MustParse(onrampoperations.Deploy.Version()),
			"",
		))
		if err != nil {
			return TokenVerifierInput{}, fmt.Errorf("failed to get on ramp address for chain %s: %w", chain.ChainID, err)
		}
		ver.OnRampAddresses[selectorStr] = onRampAddressRef.Address

		defaultExecutorOnRampAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(executor.ProxyType),
			semver.MustParse(executor.DeployProxy.Version()),
			evm.DefaultExecutorQualifier,
		))
		if err != nil {
			return TokenVerifierInput{}, fmt.Errorf("failed to get default executor on ramp address for chain %s: %w", chain.ChainID, err)
		}
		ver.DefaultExecutorOnRampAddresses[selectorStr] = defaultExecutorOnRampAddressRef.Address

		rmnRemoteAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			semver.MustParse(rmn_remote.Deploy.Version()),
			"",
		))
		if err != nil {
			return TokenVerifierInput{}, fmt.Errorf("failed to get rmn remote address for chain %s: %w", chain.ChainID, err)
		}
		ver.RMNRemoteAddresses[selectorStr] = rmnRemoteAddressRef.Address
	}

	return ver, nil
}
