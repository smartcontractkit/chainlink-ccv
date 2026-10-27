package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	adapters_1_6_1 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_1/adapters"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
	executorops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	evmchainconfig "github.com/smartcontractkit/chainlink-ccv/build/devenv/evm/chainconfig"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/localnetwork"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var tokenPoolVersions = []string{
	"1.6.1",
	"2.0.0",
}

func init() {
	registerTokenAdapters()

	// Register EVM with chainreg
	evmFactory := &ImplFactory{}
	if err := chainreg.Register(chainsel.FamilyEVM, chainreg.Registration{
		ImplFactory:              evmFactory,
		ExecutorInfo:             evmFactory,
		CLDFProvider:             NewCLDFProviderFactory(),
		ChainConfigLoader:        ChainConfigLoader,
		LocalNetworkConfigurator: localnetwork.Configurator(chainsel.FamilyEVM),
		VerifierModifier:         VerifierModifier,
		VerifierDatabases:        VerifierDatabases,
		ExecutorModifier:         ExecutorModifier,
		TokenVerifierModifier:    TokenVerifierModifier,
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
		AddressResolver:      &AddressResolver{},
		V3SourceFactory:      NewV3Source,
		V3DestinationFactory: NewV3Destination,
	}); err != nil {
		panic("evm chainreg: " + err.Error())
	}

	// Cross-family extra-args defaults until product repos register their own serializers.
	// TODO: Move Canton serializer registration into the Canton product repo.
	if err := chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
	}); err != nil {
		panic("canton extra-args chainreg: " + err.Error())
	}
	// TODO: Move Solana serializer registration into the Solana product repo.
	if err := chainreg.Register(chainsel.FamilySolana, chainreg.Registration{
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildSVMExtraArgsV1,
		},
	}); err != nil {
		panic("solana extra-args chainreg: " + err.Error())
	}
}

// verifierEVMConfig is a committee verifier's [verifier.opaque_configs.evm] section.
type verifierEVMConfig struct {
	// LogPollerSourceReaderChains are the chain IDs that read through the LogPoller; "*" is every chain.
	LogPollerSourceReaderChains []string `toml:"log_poller_source_reader_chains"`
}

// allChains in log_poller_source_reader_chains turns the LogPoller reader on for every chain.
const allChains = "*"

func (c verifierEVMConfig) logPollerOn() bool { return len(c.LogPollerSourceReaderChains) > 0 }

// evmDBName is the EVM accessor's own database, created on the verifier's DB server when the LogPoller is on.
const evmDBName = "evm_db"

// parseVerifierEVMConfig reads the verifier's opaque_configs.evm; absent means all defaults.
func parseVerifierEVMConfig(in *committeeverifier.Input) (verifierEVMConfig, error) {
	opaque, ok := in.OpaqueConfigs[chainsel.FamilyEVM]
	if !ok {
		return verifierEVMConfig{}, nil
	}
	parsed, err := util.OpaqueToConcreteStrict[verifierEVMConfig](opaque)
	if err != nil {
		return verifierEVMConfig{}, fmt.Errorf("invalid opaque_configs.evm for verifier %s: %w", in.ContainerName, err)
	}
	return *parsed, nil
}

// VerifierDatabases asks for evm_db only when the verifier reads through the LogPoller.
func VerifierDatabases(in *committeeverifier.Input) ([]string, error) {
	cfg, err := parseVerifierEVMConfig(in)
	if err != nil || !cfg.logPollerOn() {
		return nil, err
	}
	return []string{evmDBName}, nil
}

// VerifierModifier adjusts committee verifier container requests for EVM.
func VerifierModifier(req testcontainers.ContainerRequest, verifierInput *committeeverifier.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", verifierInput.ContainerName)
	cfg, err := parseVerifierEVMConfig(verifierInput)
	if err != nil {
		return req, err
	}
	req, err = addEVMConfig(req, outputs, withLogPoller(cfg.LogPollerSourceReaderChains))
	if err != nil || !cfg.logPollerOn() {
		return req, err
	}
	return addEVMSecrets(req, verifierInput)
}

// ExecutorModifier adjusts executor container requests for EVM.
func ExecutorModifier(req testcontainers.ContainerRequest, executorInput *executor.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", executorInput.ContainerName)
	return addEVMConfig(req, outputs)
}

// TokenVerifierModifier adjusts token verifier container requests for EVM.
func TokenVerifierModifier(req testcontainers.ContainerRequest, _ *services.TokenVerifierInput, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	return addEVMConfig(req, outputs)
}

// evmConfigOption adjusts the EVM config generated from the blockchain outputs for one container.
type evmConfigOption func(*evm.Config) error

// withLogPoller sets log_poller_source_reader_enabled on the listed chain IDs, or on every chain for "*".
func withLogPoller(chainIDs []string) evmConfigOption {
	return func(c *evm.Config) error {
		want := make(map[string]bool, len(chainIDs))
		for _, id := range chainIDs {
			want[id] = true
		}
		for selector, chain := range c.Chains {
			sel, err := strconv.ParseUint(selector, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid chain selector %q: %w", selector, err)
			}
			chainID, err := chainsel.GetChainIDFromSelector(sel)
			if err != nil {
				return fmt.Errorf("chain selector %s: %w", selector, err)
			}
			if want[allChains] || want[chainID] {
				chain.LogPollerSourceReaderEnabled = true
				c.Chains[selector] = chain
				delete(want, chainID)
			}
		}
		delete(want, allChains)
		if len(want) > 0 {
			return fmt.Errorf("log_poller_source_reader_chains names chain IDs %v, which are not among the verifier's chains",
				slices.Sorted(maps.Keys(want)))
		}
		return nil
	}
}

func addEVMConfig(req testcontainers.ContainerRequest, outputs []*blockchain.Output, opts ...evmConfigOption) (testcontainers.ContainerRequest, error) {
	config, err := marshalEVMConfig(outputs, opts...)
	if err != nil {
		return req, fmt.Errorf("failed to marshal EVM config: %w", err)
	}
	configFile, err := os.CreateTemp("", "ccv-evm-config-*.toml")
	if err != nil {
		return req, fmt.Errorf("failed to create EVM config file: %w", err)
	}
	configPath := configFile.Name()
	removeConfig := true
	defer func() {
		if removeConfig {
			_ = os.Remove(configPath)
		}
	}()
	if _, err := configFile.Write(config); err != nil {
		_ = configFile.Close()
		return req, fmt.Errorf("failed to write EVM config file: %w", err)
	}
	if err := configFile.Chmod(0o644); err != nil {
		_ = configFile.Close()
		return req, fmt.Errorf("failed to set EVM config file permissions: %w", err)
	}
	if err := configFile.Close(); err != nil {
		return req, fmt.Errorf("failed to close EVM config file: %w", err)
	}
	removeConfig = false

	req.Files = append(req.Files, testcontainers.ContainerFile{
		HostFilePath:      configPath,
		ContainerFilePath: evm.DefaultEVMConfigPath,
		FileMode:          0o644,
	})

	return req, nil
}

// addEVMSecrets writes the verifier's EVM secrets beside its other secrets files and bind-mounts them at
// the default path. [db] is the EVM accessor's own database.
func addEVMSecrets(req testcontainers.ContainerRequest, in *committeeverifier.Input) (testcontainers.ContainerRequest, error) {
	secrets, err := toml.Marshal(evmconfig.Secrets{DB: &evmconfig.DBConfig{URL: committeeverifier.InternalDBURL(in, evmDBName)}})
	if err != nil {
		return req, fmt.Errorf("failed to marshal EVM secrets: %w", err)
	}
	secretsFilePath := filepath.Join(util.CCVConfigDir(),
		fmt.Sprintf("evm-%s-secrets-%d.toml", in.CommitteeName, in.NodeIndex+1))
	// 0o644 like the verifier secrets: the ccv CLI run through docker exec must be able to read it.
	if err := os.WriteFile(secretsFilePath, secrets, 0o644); err != nil {
		return req, fmt.Errorf("failed to write EVM secrets to file: %w", err)
	}
	req.Mounts = append(req.Mounts, testcontainers.BindMount(secretsFilePath, evmconfig.DefaultEVMSecretsPath))
	return req, nil
}

// ImplFactory implements chainreg.ImplFactory for EVM chains.
type ImplFactory struct{}

func (f *ImplFactory) NewEmpty() cciptestinterfaces.CCIP17Configuration {
	return NewEmptyCCIP17EVM()
}

func (f *ImplFactory) New(
	ctx context.Context,
	lggr zerolog.Logger,
	env *deployment.Environment,
	chainSelector uint64,
) (cciptestinterfaces.CCIP17, error) {
	return NewCCIP17EVM(ctx, lggr, env, chainSelector)
}

// NewV3Source implements [chainreg.V3SourceFactory] for EVM chains.
//
// This is the canonical example for a chain family that wants to plug into V3
// message tests without implementing the full ImplFactory/CCIP17 surface: EVM
// happens to implement CCIP17 in full, so it simply reuses NewCCIP17EVM, but a
// family need only return a value satisfying cciptestinterfaces.V3Source here.
func NewV3Source(
	ctx context.Context,
	lggr zerolog.Logger,
	env *deployment.Environment,
	chainSelector uint64,
) (cciptestinterfaces.V3Source, error) {
	return NewCCIP17EVM(ctx, lggr, env, chainSelector)
}

// NewV3Destination implements [chainreg.V3DestinationFactory] for EVM chains.
// See NewV3Source for context on why this delegates to NewCCIP17EVM.
func NewV3Destination(
	ctx context.Context,
	lggr zerolog.Logger,
	env *deployment.Environment,
	chainSelector uint64,
) (cciptestinterfaces.V3Destination, error) {
	return NewCCIP17EVM(ctx, lggr, env, chainSelector)
}

func (f *ImplFactory) DefaultSignerKey(keys services.BootstrapKeys) string {
	return keys.ECDSAAddress
}

func (f *ImplFactory) DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string {
	evmChains := env.BlockChains.EVMChains()
	if chain, ok := evmChains[chainSelector]; ok {
		return chain.DeployerKey.From.Hex()
	}
	return ""
}

func (f *ImplFactory) SupportsFunding() bool {
	return true
}

func (f *ImplFactory) ExecutorTransmitterKeyName() string {
	return contracttransmitter.DefaultKeyName
}

func (f *ImplFactory) ExecutorTransmitterAddress(keys services.BootstrapKeys) string {
	rawHex := keys.PublicKeyHex(contracttransmitter.DefaultKeyName)
	if rawHex == "" {
		return ""
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return ""
	}
	pubKey, err := crypto.UnmarshalPubkey(raw)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(crypto.PubkeyToAddress(*pubKey).Bytes())
}

// registerTokenAdapters registers EVM token adapters so ConfigureTokensForTransfers
// can process token configs that reference these pool versions.
func registerTokenAdapters() {
	tokenAdapterRegistry := tokenscore.GetTokenAdapterRegistry()
	for _, poolVersion := range tokenPoolVersions {
		var tokenAdapter tokenscore.TokenAdapter
		tokenAdapter = &evmadapters.TokenAdapter{}
		if poolVersion == "1.6.1" {
			tokenAdapter = &adapters_1_6_1.TokenAdapter{}
		}
		version := semver.MustParse(poolVersion)
		if _, ok := tokenAdapterRegistry.GetTokenAdapter("evm", version); !ok {
			tokenAdapterRegistry.RegisterTokenAdapter("evm", version, tokenAdapter)
		}
	}
}

// NewCLDFProviderFactory returns a CLDF provider factory for EVM blockchains.
func NewCLDFProviderFactory() func(context.Context, *blockchain.Input) (cldf_chain.BlockChain, uint64, error) {
	defaultTxTimeout := 30 * time.Second
	return func(ctx context.Context, b *blockchain.Input) (cldf_chain.BlockChain, uint64, error) {
		chainID := b.Out.ChainID
		rpcWSURL := b.Out.Nodes[0].ExternalWSUrl
		rpcHTTPURL := b.Out.Nodes[0].ExternalHTTPUrl

		d, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, 0, err
		}

		var confirmer cldf_evm_provider.ConfirmFunctor
		switch b.Type {
		case blockchain.TypeAnvil:
			confirmer = cldf_evm_provider.ConfirmFuncGeth(defaultTxTimeout, cldf_evm_provider.WithTickInterval(5*time.Millisecond))
		case blockchain.TypeGeth:
			confirmer = cldf_evm_provider.ConfirmFuncGeth(defaultTxTimeout)
		default:
			return nil, 0, fmt.Errorf("EVM blockchain type %s is not supported", b.Type)
		}

		p, err := cldf_evm_provider.NewRPCChainProvider(
			d.ChainSelector,
			cldf_evm_provider.RPCChainProviderConfig{
				DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(getNetworkPrivateKey()),
				RPCs: []rpcclient.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: rpcclient.URLSchemePreferenceHTTP,
					},
				},
				UsersTransactorGen: generateUserTransactors(getUserPrivateKeys()),
				ConfirmFunctor:     confirmer,
			},
		).Initialize(ctx)
		if err != nil {
			return nil, 0, err
		}

		return p, d.ChainSelector, nil
	}
}

func generateUserTransactors(privateKeys []string) []cldf_evm_provider.SignerGenerator {
	transactors := make([]cldf_evm_provider.SignerGenerator, 0, len(privateKeys))
	for _, pk := range privateKeys {
		transactors = append(transactors, cldf_evm_provider.TransactorFromRaw(pk))
	}
	return transactors
}

func getUserPrivateKeys() []string {
	userPrivateKeys, idx := []string{getNetworkPrivateKey()}, 0
	for {
		idx++
		pk := os.Getenv(fmt.Sprintf("PRIVATE_KEY_%d", idx))
		if pk == "" {
			break
		}
		userPrivateKeys = append(userPrivateKeys, pk)
	}
	return userPrivateKeys
}

// ChainConfigLoader returns connection-free EVM chain metadata for compatibility consumers.
// Standalone services receive connection information through the EVM-local config mounted by the
// container modifier.
func ChainConfigLoader(outputs []*blockchain.Output) (map[string]any, error) {
	fullInfos, err := evmchainconfig.ConvertBlockchainOutputsToInfo(outputs)
	if err != nil {
		return nil, err
	}

	infos := make(map[string]any, len(fullInfos))
	for selector, info := range fullInfos {
		info.Nodes = nil
		infos[selector] = info
	}

	return infos, nil
}

func marshalEVMConfig(outputs []*blockchain.Output, opts ...evmConfigOption) ([]byte, error) {
	infos, err := evmchainconfig.ConvertBlockchainOutputsToInfo(outputs)
	if err != nil {
		return nil, err
	}

	cfg := evm.NewConfigFromInfos(infos)
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	config, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	return config, nil
}

func getContractAddress(ds datastore.DataStore, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) (protocol.UnknownAddress, error) {
	ref, err := ds.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s: %w",
			contractName, chainSelector, contractType, version, err)
	}
	return protocol.NewUnknownAddressFromHex(ref.Address)
}

// AddressResolver implements [chainreg.AddressResolver] for EVM chains using v2.0.0 devenv deployments.
type AddressResolver struct{}

// GetContractReceiver implements [chainreg.AddressResolver].
func (AddressResolver) GetContractReceiver(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
	return getContractAddress(ds, chainSelector,
		datastore.ContractType(mock_receiver_v2.ContractType),
		mock_receiver_v2.Deploy.Version(),
		qualifier,
		"mock receiver",
	)
}

// GetExecutor implements [chainreg.AddressResolver].
func (AddressResolver) GetExecutor(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
	return getContractAddress(ds, chainSelector,
		datastore.ContractType(sequences.ExecutorProxyType),
		executorops.Deploy.Version(),
		qualifier,
		"executor",
	)
}

// GetCommitteeCCV implements [chainreg.AddressResolver].
func (AddressResolver) GetCommitteeCCV(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
	return getContractAddress(ds, chainSelector,
		datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
		versioned_verifier_resolver.Version.String(),
		qualifier,
		"committee verifier proxy",
	)
}

// GetToken implements [chainreg.AddressResolver].
func (AddressResolver) GetToken(ds datastore.DataStore, chainSelector uint64, poolRef datastore.AddressRef) (protocol.UnknownAddress, error) {
	tokenRef, err := TokenRefForPool(poolRef)
	if err != nil {
		return protocol.UnknownAddress{}, err
	}
	return getContractAddress(ds, chainSelector, tokenRef.Type, tokenRef.Version.String(), tokenRef.Qualifier, "token")
}
