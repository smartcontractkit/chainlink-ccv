package ccv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/nonce_manager"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvTypes "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

/*
This code should be generalized and moved to devenv library after we finish CCIPv1.7 environment!
*/

type TimeTracker struct {
	logger    zerolog.Logger
	start     time.Time
	last      time.Time
	intervals []interval
}

type interval struct {
	tag   string
	delta time.Duration
}

// NewTimeTracker is a simple utility function that tracks execution time.
func NewTimeTracker(l zerolog.Logger) *TimeTracker { //nolint:gocritic
	now := time.Now()
	return &TimeTracker{
		start:     now,
		last:      now,
		logger:    l,
		intervals: make([]interval, 0),
	}
}

func (t *TimeTracker) Record(tag string) {
	now := time.Now()
	delta := now.Sub(t.last)
	t.intervals = append(t.intervals, interval{
		tag:   tag,
		delta: delta,
	})
	t.last = now
}

func (t *TimeTracker) Print() {
	total := time.Since(t.start)
	t.logger.Debug().Msg("Time tracking results:")
	for _, i := range t.intervals {
		t.logger.Debug().
			Str("Tag", i.tag).
			Str("Duration", i.delta.String()).
			Send()
	}

	t.logger.Debug().
		Str("Duration", total.String()).
		Msg("Total environment boot up time")
}

func PrintCLDFAddresses(in *Cfg) error {
	for _, addr := range in.CLDF.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		fmt.Printf("%-30s %-30s %-40s %-30s\n", "Selector", "Type", "Address", "Version")
		fmt.Println("--------------------------------------------------------------------------------------------------------------")

		for _, ref := range refs {
			fmt.Printf("%-30d %-30s %-40s %-30s\n", ref.ChainSelector, ref.Type, ref.Address, ref.Version)
		}
	}
	return nil
}

// NewDefaultCLDFBundle creates a new default CLDF bundle.
func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
}

// GetContractAddrForSelector get contract address by type and chain selector.
func GetContractAddrForSelector(in *Cfg, selector uint64, contractType datastore.ContractType) (common.Address, error) {
	var contractAddr common.Address
	for _, addr := range in.CLDF.Addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == contractType {
				contractAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return contractAddr, nil
}

func SaveContractRefsForSelector(in *Cfg, sel uint64, refs []datastore.AddressRef) error {
	var addresses []datastore.AddressRef
	var idx int
	for i, addressesForSelector := range in.CLDF.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addressesForSelector), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		if len(refs) > 0 && refs[0].ChainSelector == sel {
			addresses = refs
			idx = i
			break
		}
	}
	for _, r := range refs {
		addresses = append(addresses, r)
	}
	addrBytes, err := json.Marshal(addresses)
	if err != nil {
		return fmt.Errorf("failed to marshal addresses: %w", err)
	}
	in.CLDF.AddressesMu.Lock()
	in.CLDF.Addresses[idx] = string(addrBytes)
	in.CLDF.AddressesMu.Unlock()
	return nil
}

func MustGetContractAddressForSelector(in *Cfg, selector uint64, contractType deployment.ContractType) common.Address {
	addr, err := GetContractAddrForSelector(in, selector, datastore.ContractType(contractType))
	if err != nil {
		Plog.Fatal().Err(err).Msg("Failed to get contract address")
	}
	return addr
}

/*
CCIPv17 (CCV) specific helpers
*/

// NewV3ExtraArgs encodes v3 extra args params
func NewV3ExtraArgs(finalityConfig uint16, execAddr common.Address, execArgs, tokenArgs []byte, requiredCCVs, optionalCCVs []ccvTypes.CCV, optionalThreshold uint8) ([]byte, error) {
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
                            "name": "requiredCCV",
                            "type": "tuple[]",
                            "components": [
                                {"name": "ccvAddress", "type": "address"},
                                {"name": "args", "type": "bytes"}
                            ]
                        },
                        {
                            "name": "optionalCCV", 
                            "type": "tuple[]",
                            "components": [
                                {"name": "ccvAddress", "type": "address"},
                                {"name": "args", "type": "bytes"}
                            ]
                        },
                        {"name": "optionalThreshold", "type": "uint8"},
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
	requiredCCV := make([]struct {
		CcvAddress common.Address
		Args       []byte
	}, len(requiredCCVs))

	for i, ccv := range requiredCCVs {
		requiredCCV[i] = struct {
			CcvAddress common.Address
			Args       []byte
		}{
			CcvAddress: common.BytesToAddress(ccv.CCVAddress),
			Args:       ccv.Args,
		}
	}

	optionalCCV := make([]struct {
		CcvAddress common.Address
		Args       []byte
	}, len(optionalCCVs))

	for i, ccv := range optionalCCVs {
		optionalCCV[i] = struct {
			CcvAddress common.Address
			Args       []byte
		}{
			CcvAddress: common.BytesToAddress(ccv.CCVAddress),
			Args:       ccv.Args,
		}
	}

	// Struct matching exactly the Solidity EVMExtraArgsV3 order and types
	extraArgs := struct {
		RequiredCCV []struct {
			CcvAddress common.Address
			Args       []byte
		}
		OptionalCCV []struct {
			CcvAddress common.Address
			Args       []byte
		}
		OptionalThreshold uint8
		FinalityConfig    uint16
		Executor          common.Address
		ExecutorArgs      []byte
		TokenArgs         []byte
	}{
		RequiredCCV:       requiredCCV,
		OptionalCCV:       optionalCCV,
		OptionalThreshold: optionalThreshold,
		FinalityConfig:    finalityConfig,
		Executor:          execAddr,
		ExecutorArgs:      execArgs,
		TokenArgs:         tokenArgs,
	}

	encoded, err := parsedABI.Methods["encodeEVMExtraArgsV3"].Inputs.Pack(extraArgs)
	if err != nil {
		return nil, err
	}

	// Prepend the GENERIC_EXTRA_ARGS_V3_TAG
	tag := []byte{0x30, 0x23, 0x26, 0xcb}
	return append(tag, encoded...), nil
}

// SendExampleArgsV2Message sends an example message between two chains (selectors) using ArgsV2.
func SendExampleArgsV2Message(in *Cfg, src, dest uint64) error {
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	chains := e.BlockChains.EVMChains()
	if chains == nil {
		return errors.New("no EVM chains found")
	}
	if !slices.Contains(selectors, src) {
		return fmt.Errorf("source selector %d not found in environment selectors %v", src, selectors)
	}
	if !slices.Contains(selectors, dest) {
		return fmt.Errorf("destination selector %d not found in environment selectors %v", dest, selectors)
	}

	srcChain := chains[src]

	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(in, srcChain.Selector, datastore.ContractType(router.ContractType))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	receiver := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"
	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiver).Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    []byte{},
		},
	}

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to send CCIP message: %w", err)
	}
	Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")

	return nil
}

// SendExampleArgsV3Message sends an example message between two chains (selectors) using ArgsV3.
func SendExampleArgsV3Message(in *Cfg, src, dest uint64, finality uint16, execAddr common.Address, execArgs, tokenArgs []byte, ccv, optCcv []ccvTypes.CCV, threshold uint8) error {
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	chains := e.BlockChains.EVMChains()
	if chains == nil {
		return errors.New("no EVM chains found")
	}
	if !slices.Contains(selectors, src) {
		return fmt.Errorf("source selector %d not found in environment selectors %v", src, selectors)
	}
	if !slices.Contains(selectors, dest) {
		return fmt.Errorf("destination selector %d not found in environment selectors %v", dest, selectors)
	}

	srcChain := chains[src]

	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(in, srcChain.Selector, datastore.ContractType(router.ContractType))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	argsV3, err := NewV3ExtraArgs(finality, execAddr, execArgs, tokenArgs, ccv, optCcv, threshold)
	if err != nil {
		return fmt.Errorf("failed to generate GenericExtraArgsV3: %w", err)
	}
	receiverAddress := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiverAddress).Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsV3,
		},
	}

	// TODO: not supported right now
	//feeReport, err := operations.ExecuteOperation(bundle, router.GetFee, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
	//	ChainSelector: srcChain.Selector,
	//	Address:       routerAddr,
	//	Args:          ccipSendArgs,
	//})
	//if err != nil {
	//	return fmt.Errorf("failed to get fee: %w", err)
	//}
	//ccipSendArgs.Value = feeReport.Output

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to send CCIP message: %w", err)
	}

	Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")

	return nil
}

func DeployMockReceiver(in *Cfg, selector uint64, args mock_receiver.ConstructorArgs) error {
	in.CLDF.AddressesMu = &sync.Mutex{}
	_, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	receiver, err := DeployReceiverForSelector(e, selector, args)
	if err != nil {
		return fmt.Errorf("failed to deploy mock receiver for selector %d: %w", selector, err)
	}

	err = SaveContractRefsForSelector(in, selector, []datastore.AddressRef{receiver})
	if err != nil {
		return fmt.Errorf("failed to save contract refs for selector %d: %w", selector, err)
	}

	return Store(in)
}

func DeployAndConfigureNewCommitCCV(in *Cfg, signatureConfigArgs commit_offramp.SignatureConfigArgs) error {
	in.CLDF.AddressesMu = &sync.Mutex{}
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	for _, sel := range selectors {
		onRamp, offRamp, err := DeployCommitVerifierForSelector(
			e,
			sel,
			commit_onramp.ConstructorArgs{
				DynamicConfig: commit_onramp.DynamicConfig{
					FeeQuoter:      MustGetContractAddressForSelector(in, sel, fee_quoter_v2.ContractType),
					FeeAggregator:  e.BlockChains.EVMChains()[sel].DeployerKey.From,
					AllowlistAdmin: e.BlockChains.EVMChains()[sel].DeployerKey.From,
				},
			},
			commit_offramp.ConstructorArgs{
				NonceManager: MustGetContractAddressForSelector(in, sel, nonce_manager.ContractType),
			},
			signatureConfigArgs,
		)
		if err != nil {
			return fmt.Errorf("failed to deploy commit onramp and offramp for selector %d: %w", sel, err)
		}

		var destConfigArgs []commit_onramp.DestChainConfigArgs
		for _, destSel := range selectors {
			if destSel == sel {
				continue
			}
			destConfigArgs = append(destConfigArgs, commit_onramp.DestChainConfigArgs{
				AllowlistEnabled:  false,
				Router:            MustGetContractAddressForSelector(in, sel, router.ContractType),
				DestChainSelector: destSel,
			})
		}

		err = ConfigureCommitVerifierOnSelectorForLanes(e, sel, common.HexToAddress(onRamp.Address), destConfigArgs)
		if err != nil {
			return fmt.Errorf("failed to configure commit onramp for selector %d: %w", sel, err)
		}

		err = SaveContractRefsForSelector(in, sel, []datastore.AddressRef{onRamp, offRamp})
		if err != nil {
			return fmt.Errorf("failed to save contract refs for selector %d: %w", sel, err)
		}
	}

	return Store(in)
}
