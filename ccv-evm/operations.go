package ccv_evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// DeployCommitVerifierForSelector deploys a new verifier to the given chain selector.
func DeployCommitVerifierForSelector(
	e *deployment.Environment,
	selector uint64,
	committeeVerifierConstructorArgs committee_verifier.ConstructorArgs,
	signatureConfigArgs committee_verifier.SetSignatureConfigArgs,
) (committeeVerifier datastore.AddressRef, err error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		err = fmt.Errorf("no EVM chain found for selector %d", selector)
		return committeeVerifier, err
	}
	committeeVerifierReport, err := operations.ExecuteOperation(e.OperationsBundle, committee_verifier.Deploy, chain, contract.DeployInput[committee_verifier.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          committeeVerifierConstructorArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to deploy Committee Verifier: %w", err)
		return committeeVerifier, err
	}
	_, err = operations.ExecuteOperation(e.OperationsBundle, committee_verifier.SetSignatureConfigs, chain, contract.FunctionInput[committee_verifier.SetSignatureConfigArgs]{
		Address:       common.HexToAddress(committeeVerifierReport.Output.Address),
		ChainSelector: chain.Selector,
		Args:          signatureConfigArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to set CommitOffRamp signature config: %w", err)
		return committeeVerifier, err
	}
	return committeeVerifierReport.Output, err
}

// ConfigureCommitVerifierOnSelectorForLanes configures an existing verifier on the given chain selector for the given lanes.
func ConfigureCommitVerifierOnSelectorForLanes(e *deployment.Environment, selector uint64, committeeVerifier common.Address, destConfigArgs []committee_verifier.DestChainConfigArgs) error {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return fmt.Errorf("no EVM chain found for selector %d", selector)
	}

	_, err := operations.ExecuteOperation(e.OperationsBundle, committee_verifier.ApplyDestChainConfigUpdates, chain, contract.FunctionInput[[]committee_verifier.DestChainConfigArgs]{
		ChainSelector: chain.Selector,
		Address:       committeeVerifier,
		Args:          destConfigArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to apply dest chain config updates to CommitteeVerifier(%s) on chain %s: %w", committeeVerifier, chain, err)
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

// NewV3ExtraArgs encodes v3 extra args params.
func NewV3ExtraArgs(finalityConfig uint16, execAddr string, execArgs, tokenArgs []byte, ccvs []protocol.CCV) ([]byte, error) {
	// ABI definition matching the exact Solidity struct EVMExtraArgsV3
	const clientABI = `
    [
        {
            "name": "encodeEVMExtraArgsV3",
            "type": "function",
            "inputs": [
                {
                    "components": [
                        {
                            "name": "ccvs", 
                            "type": "tuple[]",
                            "components": [
                                {"name": "ccvAddress", "type": "address"},
                                {"name": "args", "type": "bytes"}
                            ]
                        },
                        {"name": "finalityConfig", "type": "uint16"},
                        {"name": "executor", "type": "address"},
                        {"name": "executorArgs", "type": "bytes"},
                        {"name": "tokenArgs", "type": "bytes"}
                    ],
                    "name": "extraArgs",
                    "type": "tuple"
                }
            ],
            "outputs": [{"type": "bytes"}],
            "stateMutability": "pure"
        }
    ]
    `

	parsedABI, err := abi.JSON(bytes.NewReader([]byte(clientABI)))
	if err != nil {
		return nil, err
	}

	// Convert CCV slices to match Solidity CCV struct exactly
	ccvStructs := make([]struct {
		CcvAddress common.Address
		Args       []byte
	}, len(ccvs))

	for i, ccv := range ccvs {
		ccvStructs[i] = struct {
			CcvAddress common.Address
			Args       []byte
		}{
			CcvAddress: common.BytesToAddress(ccv.CCVAddress),
			Args:       ccv.Args,
		}
	}

	// Struct matching exactly the Solidity EVMExtraArgsV3 order and types
	extraArgs := struct {
		Ccvs []struct {
			CcvAddress common.Address
			Args       []byte
		}
		FinalityConfig uint16
		Executor       common.Address
		ExecutorArgs   []byte
		TokenArgs      []byte
	}{
		Ccvs:           ccvStructs,
		FinalityConfig: finalityConfig,
		Executor:       common.HexToAddress(execAddr),
		ExecutorArgs:   execArgs,
		TokenArgs:      tokenArgs,
	}

	encoded, err := parsedABI.Methods["encodeEVMExtraArgsV3"].Inputs.Pack(extraArgs)
	if err != nil {
		return nil, err
	}

	// Prepend the GENERIC_EXTRA_ARGS_V3_TAG
	tag := []byte{0x30, 0x23, 0x26, 0xcb}
	return append(tag, encoded...), nil
}

func DeployMockReceiver(ctx context.Context, e *deployment.Environment, addresses []string, selector uint64, args mock_receiver.ConstructorArgs) ([]string, error) {
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	receiver, err := DeployReceiverForSelector(e, selector, args)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy mock receiver for selector %d: %w", selector, err)
	}

	addrs, err := MergeAddresses(addresses, selector, []datastore.AddressRef{receiver})
	if err != nil {
		return nil, fmt.Errorf("failed to save contract refs for selector %d: %w", selector, err)
	}

	return addrs, nil
}

func DeployAndConfigureNewCommitCCV(ctx context.Context, e *deployment.Environment, addresses []string, selectors []uint64, signatureConfigArgs committee_verifier.SetSignatureConfigArgs) ([]string, error) {
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	allAddrs := make([]string, 0)

	for _, sel := range selectors {
		committeeVerifier, err := DeployCommitVerifierForSelector(
			e,
			sel,
			committee_verifier.ConstructorArgs{
				DynamicConfig: committee_verifier.DynamicConfig{
					FeeQuoter:      MustGetContractAddressForSelector(addresses, sel, fee_quoter.ContractType),
					FeeAggregator:  e.BlockChains.EVMChains()[sel].DeployerKey.From,
					AllowlistAdmin: e.BlockChains.EVMChains()[sel].DeployerKey.From,
				},
			},
			signatureConfigArgs,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to deploy commit onramp and offramp for selector %d: %w", sel, err)
		}
		addrs, err := MergeAddresses(addresses, sel, []datastore.AddressRef{committeeVerifier})
		if err != nil {
			return nil, fmt.Errorf("failed to save contract refs for selector %d: %w", sel, err)
		}
		allAddrs = append(allAddrs, addrs...)
	}

	for _, sel := range selectors {
		var destConfigArgs []committee_verifier.DestChainConfigArgs
		for _, destSel := range selectors {
			if destSel == sel {
				continue
			}
			destConfigArgs = append(destConfigArgs, committee_verifier.DestChainConfigArgs{
				AllowlistEnabled:   false,
				Router:             MustGetContractAddressForSelector(addresses, sel, router.ContractType),
				DestChainSelector:  destSel,
				GasForVerification: 1, // TODO: set proper gas limit
				// TODO: Missing fields?
				//FeeUSDCents        uint16
				//PayloadSizeBytes   uint32
			})
		}

		err := ConfigureCommitVerifierOnSelectorForLanes(e, sel, MustGetContractAddressForSelector(addresses, sel, committee_verifier.ContractType), destConfigArgs)
		if err != nil {
			return nil, fmt.Errorf("failed to configure commit onramp for selector %d: %w", sel, err)
		}
	}

	return allAddrs, nil
}

func MergeAddresses(addrs []string, sel uint64, refs []datastore.AddressRef) ([]string, error) {
	addresses := make([]datastore.AddressRef, 0)
	for _, addressesForSelector := range addrs {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addressesForSelector), &refs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		if len(refs) > 0 && refs[0].ChainSelector == sel {
			addresses = refs
			break
		}
	}
	addresses = append(addresses, refs...)
	addrBytes, err := json.Marshal(addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal addresses: %w", err)
	}
	addrs = append(addrs, string(addrBytes))
	return addrs, nil
}

func MustGetContractAddressForSelector(addresses []string, selector uint64, contractType deployment.ContractType) common.Address {
	addr, err := GetContractAddrForSelector(addresses, selector, datastore.ContractType(contractType))
	if err != nil {
		panic("failed to get contract address")
	}
	return addr
}
