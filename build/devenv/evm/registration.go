package evm

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	adapters_1_6_1 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_1/adapters"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
)

var tokenPoolVersions = []string{
	"1.6.1",
	"2.0.0",
}

func init() {
	registerTokenAdapters()

	// Register EVM with chainreg
	if err := chainreg.Register(chainsel.FamilyEVM, chainreg.Registration{
		ImplFactory:       &ImplFactory{},
		CLDFProvider:      NewCLDFProviderFactory(),
		ChainConfigLoader: ChainConfigLoader,
		VerifierModifier:  VerifierModifier,
		ExecutorModifier:  ExecutorModifier,
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
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

// VerifierModifier adjusts committee verifier container requests for EVM.
func VerifierModifier(req testcontainers.ContainerRequest, verifierInput *committeeverifier.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", verifierInput.ContainerName)
	return req, nil
}

// ExecutorModifier adjusts executor container requests for EVM.
func ExecutorModifier(req testcontainers.ContainerRequest, executorInput *executor.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", executorInput.ContainerName)
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

// ChainConfigLoader converts CTF blockchain outputs to a map of chain selector to evm.Info.
func ChainConfigLoader(outputs []*blockchain.Output) (map[string]any, error) {
	infos := make(map[string]any)
	for _, output := range outputs {
		if output.Family != chainsel.FamilyEVM {
			continue
		}
		info := &evm.Info{
			ChainID:         output.ChainID,
			Type:            output.Type,
			Family:          output.Family,
			UniqueChainName: output.ContainerName,
			Nodes:           make([]evm.Node, 0, len(output.Nodes)),
		}

		for _, node := range output.Nodes {
			if node != nil {
				info.Nodes = append(info.Nodes, evm.Node{
					ExternalHTTPUrl: node.ExternalHTTPUrl,
					InternalHTTPUrl: node.InternalHTTPUrl,
					ExternalWSUrl:   node.ExternalWSUrl,
					InternalWSUrl:   node.InternalWSUrl,
				})
			}
		}

		details, err := chainsel.GetChainDetailsByChainIDAndFamily(output.ChainID, output.Family)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for chain %s, family %s: %w", output.ChainID, output.Family, err)
		}

		infos[strconv.FormatUint(details.ChainSelector, 10)] = info
	}

	return infos, nil
}
