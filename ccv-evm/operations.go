package ccv_evm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

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
