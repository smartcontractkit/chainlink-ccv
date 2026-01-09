package services

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

//go:embed committeeVerifier.template.toml
var committeeVerifierConfigTemplate string

const (
	DefaultVerifierName    = "verifier"
	DefaultVerifierDBName  = "verifier-db"
	DefaultVerifierImage   = "verifier:dev"
	DefaultVerifierPort    = 8100
	DefaultVerifierDBPort  = 8432
	DefaultVerifierSQLInit = "init.sql"
	DefaultVerifierMode    = Standalone

	DefaultVerifierDBImage = "postgres:16-alpine"
)

var DefaultVerifierDBConnectionString = fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
	DefaultVerifierName, DefaultVerifierName, DefaultVerifierDBPort, DefaultVerifierName)

// ConvertBlockchainOutputsToInfo converts blockchain.Output to BlockchainInfo.
func ConvertBlockchainOutputsToInfo(outputs []*blockchain.Output) map[string]*protocol.BlockchainInfo {
	infos := make(map[string]*protocol.BlockchainInfo)
	for _, output := range outputs {
		info := &protocol.BlockchainInfo{
			ChainID:         output.ChainID,
			Type:            output.Type,
			Family:          output.Family,
			UniqueChainName: output.ContainerName,
			Nodes:           make([]*protocol.Node, 0, len(output.Nodes)),
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

type VerifierEnvConfig struct {
	AggregatorAPIKey    string `toml:"aggregator_api_key"`
	AggregatorSecretKey string `toml:"aggregator_secret_key"`
}

type VerifierInput struct {
	Mode           Mode             `toml:"mode"`
	DB             *VerifierDBInput `toml:"db"`
	Out            *VerifierOutput  `toml:"out"`
	Image          string           `toml:"image"`
	SourceCodePath string           `toml:"source_code_path"`
	RootPath       string           `toml:"root_path"`
	// TODO: Rename to VerifierID -- maps to this value in verifier.Config
	ContainerName     string             `toml:"container_name"`
	Port              int                `toml:"port"`
	UseCache          bool               `toml:"use_cache"`
	AggregatorAddress string             `toml:"aggregator_address"`
	Env               *VerifierEnvConfig `toml:"env"`
	CommitteeName     string             `toml:"committee_name"`
	NodeIndex         int                `toml:"node_index"`

	// SigningKey is generated during the deploy step.
	SigningKey string `toml:"signing_key"`
	// SigningKeyPublic is generated during the deploy step.
	// Maps to signer_address in the verifier config toml.
	SigningKeyPublic string `toml:"signing_key_public"`

	// Contract addresses used to generate configs
	// Maps to on_ramp_addresses in the verifier config toml.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// Maps to committee_verifier_addresses in the verifier config toml.
	CommitteeVerifierAddresses map[string]string `toml:"committee_verifier_addresses"`
	// Maps to default_executor_on_ramp_addresses in the verifier config toml.
	DefaultExecutorOnRampAddresses map[string]string `toml:"default_executor_on_ramp_addresses"`
	// Maps to rmn_remote_addresses in the verifier config toml.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
	// Maps to Monitoring.Beholder.OtelExporterHTTPEndpoint in the verifier config toml.
	MonitoringOtelExporterHTTPEndpoint string `toml:"monitoring_otel_exporter_http_endpoint"`
	// Maps to blockchain_infos in the verifier config toml.
	// NOTE: this should be removed from the verifier app config toml and into another config file
	// that is specifically for standalone mode verifiers.
	BlockchainInfos map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`

	// TLSCACertFile is the path to the CA certificate file for TLS verification.
	// This is set by the aggregator service and used to trust the self-signed CA.
	TLSCACertFile string `toml:"-"`

	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	// Only use for CL node tests where certificates cannot be injected.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`

	// AggregatorOutput is optionally set to automatically obtain credentials.
	// If Env is nil or has empty credentials, credentials will be looked up from here.
	AggregatorOutput *AggregatorOutput `toml:"-"`
}

func (v *VerifierInput) GenerateJobSpec() (verifierJobSpec string, err error) {
	tomlConfigBytes, err := v.GenerateConfig()
	if err != nil {
		return "", fmt.Errorf("failed to generate verifier config: %w", err)
	}
	return fmt.Sprintf(
		`
schemaVersion = 1
type = "ccvcommitteeverifier"
committeeVerifierConfig = """
%s
"""
`, string(tomlConfigBytes),
	), nil
}

func (v *VerifierInput) buildVerifierConfiguration(config *commit.Config) error {
	if _, err := toml.Decode(committeeVerifierConfigTemplate, &config); err != nil {
		return fmt.Errorf("failed to decode verifier config template: %w", err)
	}

	config.VerifierID = v.ContainerName
	config.AggregatorAddress = v.AggregatorAddress
	config.SignerAddress = v.SigningKeyPublic
	config.CommitteeVerifierAddresses = v.CommitteeVerifierAddresses
	config.OnRampAddresses = v.OnRampAddresses
	config.DefaultExecutorOnRampAddresses = v.DefaultExecutorOnRampAddresses
	config.RMNRemoteAddresses = v.RMNRemoteAddresses
	config.InsecureAggregatorConnection = v.InsecureAggregatorConnection

	// The value in the template should be usable for devenv setups, only override if a different value is provided.
	if v.MonitoringOtelExporterHTTPEndpoint != "" {
		config.Monitoring.Beholder.OtelExporterHTTPEndpoint = v.MonitoringOtelExporterHTTPEndpoint
	}

	return nil
}

func (v *VerifierInput) GenerateConfigWithBlockchainInfos(blockchainInfos map[string]*protocol.BlockchainInfo) (verifierTomlConfig []byte, err error) {
	// Build base configuration
	var baseConfig commit.Config
	if err := v.buildVerifierConfiguration(&baseConfig); err != nil {
		return nil, err
	}

	// Wrap in ConfigWithBlockchainInfo and add blockchain infos
	config := commit.ConfigWithBlockchainInfos{
		Config:          baseConfig,
		BlockchainInfos: blockchainInfos,
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}

	return cfg, nil
}

func (v *VerifierInput) GenerateConfig() (verifierTomlConfig []byte, err error) {
	var config commit.Config
	err = v.buildVerifierConfiguration(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to build verifier configuration: %w", err)
	}

	cfg, err := toml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier config to TOML: %w", err)
	}

	return cfg, nil
}

type VerifierOutput struct {
	ContainerName      string `toml:"container_name"`
	ExternalHTTPURL    string `toml:"http_url"`
	InternalHTTPURL    string `toml:"internal_http_url"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
	UseCache           bool   `toml:"use_cache"`
}

func ApplyVerifierDefaults(in VerifierInput) VerifierInput {
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
	if in.Mode == "" {
		in.Mode = DefaultVerifierMode
	}
	return in
}

func NewVerifier(in *VerifierInput) (*VerifierOutput, error) {
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

	/* Database */
	_, err = postgres.Run(ctx,
		in.DB.Image,
		testcontainers.WithName(in.DB.Name),
		postgres.WithDatabase(in.ContainerName),
		postgres.WithUsername(in.ContainerName),
		postgres.WithPassword(in.ContainerName),
		postgres.WithInitScripts(filepath.Join(p, DefaultVerifierSQLInit)),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name:         in.DB.Name,
				ExposedPorts: []string{"5432/tcp"},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {in.DB.Name},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = nat.PortMap{
						"5432/tcp": []nat.PortBinding{
							{HostPort: strconv.Itoa(in.DB.Port)},
						},
					}
				},
				WaitingFor: wait.ForAll(
					wait.ForLog("database system is ready to accept connections"),
					wait.ForListeningPort("5432/tcp"),
				),
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	envVars := make(map[string]string)

	var apiKey, secretKey string

	if in.Env != nil && in.Env.AggregatorAPIKey != "" && in.Env.AggregatorSecretKey != "" {
		apiKey = in.Env.AggregatorAPIKey
		secretKey = in.Env.AggregatorSecretKey
	} else if in.AggregatorOutput != nil {
		creds, ok := in.AggregatorOutput.GetCredentialsForClient(in.ContainerName)
		if ok {
			apiKey = creds.APIKey
			secretKey = creds.Secret
		}
	}

	if apiKey == "" || secretKey == "" {
		return nil, fmt.Errorf("failed to get HMAC credentials for verifier %s: no credentials provided via Env or AggregatorOutput", in.ContainerName)
	}

	envVars["VERIFIER_AGGREGATOR_API_KEY"] = apiKey
	envVars["VERIFIER_AGGREGATOR_SECRET_KEY"] = secretKey

	if in.SigningKey != "" {
		envVars["VERIFIER_SIGNER_PRIVATE_KEY"] = in.SigningKey
	}

	// Database connection for chain status (internal docker network address)
	internalDBConnectionString := fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
		in.ContainerName, in.ContainerName, in.DB.Name, in.ContainerName)
	envVars["CL_DATABASE_URL"] = internalDBConnectionString

	// Generate and store config file.
	config, err := in.GenerateConfigWithBlockchainInfos(blockchainInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verifier config for committee %s: %w", in.CommitteeName, err)
	}
	confDir := util.CCVConfigDir()
	configFilePath := filepath.Join(confDir,
		fmt.Sprintf("verifier-%s-config-%d.toml", in.CommitteeName, in.NodeIndex+1))
	if err := os.WriteFile(configFilePath, config, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write aggregator config to file: %w", err)
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

	// Mount CA cert for TLS verification if provided. Only our self-signed CA is used for now.
	if in.TLSCACertFile != "" {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			HostFilePath:      in.TLSCACertFile,
			ContainerFilePath: "/etc/ssl/certs/ca-certificates.crt",
			FileMode:          0o644,
		})
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

	return &VerifierOutput{
		ContainerName:   in.ContainerName,
		ExternalHTTPURL: fmt.Sprintf("http://%s:%d", host, in.Port),
		InternalHTTPURL: fmt.Sprintf("http://%s:%d", in.ContainerName, in.Port),
		DBConnectionString: fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
			in.ContainerName, in.ContainerName, in.DB.Port, in.ContainerName),
	}, nil
}

func ResolveContractsForVerifier(ds datastore.DataStore, blockchains []*blockchain.Input, ver VerifierInput) (VerifierInput, error) {
	ver.OnRampAddresses = make(map[string]string)
	ver.CommitteeVerifierAddresses = make(map[string]string)
	ver.DefaultExecutorOnRampAddresses = make(map[string]string)
	ver.RMNRemoteAddresses = make(map[string]string)

	for _, chain := range blockchains {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(chain.ChainID, chainsel.FamilyEVM)
		if err != nil {
			return VerifierInput{}, err
		}
		selectorStr := strconv.FormatUint(networkInfo.ChainSelector, 10)

		onRampAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(onrampoperations.ContractType),
			semver.MustParse(onrampoperations.Deploy.Version()),
			"",
		))
		if err != nil {
			return VerifierInput{}, fmt.Errorf("failed to get on ramp address for chain %s: %w", chain.ChainID, err)
		}
		ver.OnRampAddresses[selectorStr] = onRampAddressRef.Address

		committeeVerifierAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			ver.CommitteeName,
		))
		if err != nil {
			return VerifierInput{}, fmt.Errorf("failed to get committee verifier address for chain %s: %w", chain.ChainID, err)
		}
		ver.CommitteeVerifierAddresses[selectorStr] = committeeVerifierAddressRef.Address

		defaultExecutorOnRampAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(executor.ProxyType),
			semver.MustParse(executor.DeployProxy.Version()),
			evm.DefaultExecutorQualifier,
		))
		if err != nil {
			return VerifierInput{}, fmt.Errorf("failed to get default executor on ramp address for chain %s: %w", chain.ChainID, err)
		}
		ver.DefaultExecutorOnRampAddresses[selectorStr] = defaultExecutorOnRampAddressRef.Address

		rmnRemoteAddressRef, err := ds.Addresses().Get(datastore.NewAddressRefKey(
			networkInfo.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			semver.MustParse(rmn_remote.Deploy.Version()),
			"",
		))
		if err != nil {
			return VerifierInput{}, fmt.Errorf("failed to get rmn remote address for chain %s: %w", chain.ChainID, err)
		}
		ver.RMNRemoteAddresses[selectorStr] = rmnRemoteAddressRef.Address
	}

	return ver, nil
}
