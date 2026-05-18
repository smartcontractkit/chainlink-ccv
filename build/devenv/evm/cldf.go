package evm

import (
	"context"
	"fmt"
	"os"
	"time"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

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
