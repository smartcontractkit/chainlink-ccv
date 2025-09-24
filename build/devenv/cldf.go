package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
)

var Plog = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Fields(map[string]any{"component": "ccv"}).Logger()

type CLDF struct {
	// Contracts (CLDF)
	AddressesMu *sync.Mutex         `toml:"-"`
	Addresses   []string            `toml:"addresses"`
	DataStore   datastore.DataStore `toml:"-"`
}

func NewCLDFOperationsEnvironment(bc []*blockchain.Input) ([]uint64, *deployment.Environment, error) {
	providers := make([]cldf_chain.BlockChain, 0)
	selectors := make([]uint64, 0)
	for _, b := range bc {
		chainID := b.Out.ChainID
		rpcWSURL := b.Out.Nodes[0].ExternalWSUrl
		rpcHTTPURL := b.Out.Nodes[0].ExternalHTTPUrl

		d, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, nil, err
		}
		selectors = append(selectors, d.ChainSelector)

		p, err := cldf_evm_provider.NewRPCChainProvider(
			d.ChainSelector,
			cldf_evm_provider.RPCChainProviderConfig{
				DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(
					getNetworkPrivateKey(),
				),
				RPCs: []deployment.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: deployment.URLSchemePreferenceHTTP,
					},
				},
				ConfirmFunctor: cldf_evm_provider.ConfirmFuncGeth(1 * time.Minute),
			},
		).Initialize(context.Background())
		if err != nil {
			return nil, nil, err
		}
		providers = append(providers, p)
	}

	blockchains := cldf_chain.NewBlockChainsFromSlice(providers)

	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		return nil, nil, err
	}

	e := deployment.Environment{
		GetContext:  func() context.Context { return context.Background() },
		Logger:      lggr,
		BlockChains: blockchains,
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
	return selectors, &e, nil
}

// DeployCommitVerifierForSelector deploys a new verifier to the given chain selector.
func DeployCommitVerifierForSelector(
	e *deployment.Environment,
	selector uint64,
	onRampConstructorArgs commit_onramp.ConstructorArgs,
	offRampConstructorArgs commit_offramp.ConstructorArgs,
	signatureConfigArgs commit_offramp.SignatureConfigArgs,
) (onRamp, offRamp datastore.AddressRef, err error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		err = fmt.Errorf("no EVM chain found for selector %d", selector)
		return onRamp, offRamp, err
	}
	commitOnRampReport, err := operations.ExecuteOperation(e.OperationsBundle, commit_onramp.Deploy, chain, contract.DeployInput[commit_onramp.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          onRampConstructorArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to deploy CommitOnRamp: %w", err)
		return onRamp, offRamp, err
	}
	commitOffRampReport, err := operations.ExecuteOperation(e.OperationsBundle, commit_offramp.Deploy, chain, contract.DeployInput[commit_offramp.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          offRampConstructorArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to deploy CommitOnRamp: %w", err)
		return onRamp, offRamp, err
	}
	_, err = operations.ExecuteOperation(e.OperationsBundle, commit_offramp.SetSignatureConfigs, chain, contract.FunctionInput[commit_offramp.SignatureConfigArgs]{
		Address:       common.HexToAddress(commitOffRampReport.Output.Address),
		ChainSelector: chain.Selector,
		Args:          signatureConfigArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to set CommitOffRamp signature config: %w", err)
		return onRamp, offRamp, err
	}
	onRamp = commitOnRampReport.Output
	offRamp = commitOffRampReport.Output
	return onRamp, offRamp, err
}

// ConfigureCommitVerifierOnSelectorForLanes configures an existing verifier on the given chain selector for the given lanes.
func ConfigureCommitVerifierOnSelectorForLanes(e *deployment.Environment, selector uint64, commitOnRamp common.Address, destConfigArgs []commit_onramp.DestChainConfigArgs) error {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return fmt.Errorf("no EVM chain found for selector %d", selector)
	}

	_, err := operations.ExecuteOperation(e.OperationsBundle, commit_onramp.ApplyDestChainConfigUpdates, chain, contract.FunctionInput[[]commit_onramp.DestChainConfigArgs]{
		ChainSelector: chain.Selector,
		Address:       commitOnRamp,
		Args:          destConfigArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to apply dest chain config updates to CommitOnRamp(%s) on chain %s: %w", commitOnRamp, chain, err)
	}

	return nil
}

// DeployReceiverForSelector deploys a new mock receiver to the given chain selector.
func DeployReceiverForSelector(e *deployment.Environment, selector uint64, args mock_receiver.ConstructorArgs) (datastore.AddressRef, error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return datastore.AddressRef{}, fmt.Errorf("no EVM chain found for selector %d", selector)
	}
	report, err := operations.ExecuteOperation(e.OperationsBundle, mock_receiver.Deploy, chain, contract.DeployInput[mock_receiver.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          args,
	})
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("failed to deploy MockReceiver: %w", err)
	}
	return report.Output, nil
}
