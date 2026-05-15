package ccv

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/registry"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func init() {
	RegisterImplFactory(chainsel.FamilyEVM, &evmImplFactory{})
	registry.RegisterCLDFProviderFactory(blockchain.FamilyEVM, newEVMCLDFProviderFactory())
}

// evmImplFactory implements ImplFactory for EVM chains, delegating to the evm
// package's constructors. It lives in the ccv package (rather than evm) to
// avoid a circular import: the ImplFactory interface references *Cfg which is
// defined here.
type evmImplFactory struct{}

func (f *evmImplFactory) NewEmpty() cciptestinterfaces.CCIP17Configuration {
	return evm.NewEmptyCCIP17EVM()
}

func (f *evmImplFactory) New(
	ctx context.Context,
	cfg *Cfg,
	lggr zerolog.Logger,
	env *deployment.Environment,
	bc *blockchain.Input,
) (cciptestinterfaces.CCIP17, error) {
	chainID := bc.ChainID
	wsURL := bc.Out.Nodes[0].ExternalWSUrl
	return evm.NewCCIP17EVM(ctx, lggr, env, chainID, wsURL)
}

func (f *evmImplFactory) NewFromCLDFEnv(
	lggr zerolog.Logger,
	env *deployment.Environment,
	chainSelector uint64,
) (cciptestinterfaces.CCIP17, error) {
	return evm.NewCCIP17EVMFromCLDFEnv(env, chainSelector)
}

func (f *evmImplFactory) DefaultSignerKey(keys services.BootstrapKeys) string {
	return keys.ECDSAAddress
}

func (f *evmImplFactory) DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string {
	evmChains := env.BlockChains.EVMChains()
	if chain, ok := evmChains[chainSelector]; ok {
		return chain.DeployerKey.From.Hex()
	}
	return ""
}

func (f *evmImplFactory) SupportsFunding() bool {
	return true
}

// newEVMCLDFProviderFactory returns a CLDFProviderFactory that builds an EVM
// CLDF BlockChain provider from the blockchain input. This extracts the inline
// EVM branch formerly in NewCLDFOperationsEnvironmentWithOffchain.
func newEVMCLDFProviderFactory() registry.CLDFProviderFactory {
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
				DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(
					getNetworkPrivateKey(),
				),
				RPCs: []rpcclient.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: rpcclient.URLSchemePreferenceHTTP,
					},
				},
				UsersTransactorGen: GenerateUserTransactors(GetUserPrivateKeys()),
				ConfirmFunctor:     confirmer,
			},
		).Initialize(ctx)
		if err != nil {
			return nil, 0, err
		}

		return p, d.ChainSelector, nil
	}
}
