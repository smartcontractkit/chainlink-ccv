package evm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
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

var (
	GenericExtraArgsV3Tag = []byte{0x30, 0x23, 0x26, 0xcb}
)

const (
	// MaxCCVsPerMessage is the maximum number of CCVs that can be included in a single message.
	// Limited by uint8 encoding in GenericExtraArgsV3 format.
	MaxCCVsPerMessage = 255

	// EVMAddressLength is the standard length of an EVM address in bytes.
	EVMAddressLength = 20

	// MaxCCVArgsLength is the maximum length of CCV-specific arguments.
	// Limited by uint16 encoding in GenericExtraArgsV3 format.
	MaxCCVArgsLength = 65535

	// MaxExecutorArgsLength is the maximum length of executor arguments.
	// Limited by uint16 encoding in GenericExtraArgsV3 format.
	MaxExecutorArgsLength = 65535

	// MaxTokenArgsLength is the maximum length of token arguments.
	// Limited by uint16 encoding in GenericExtraArgsV3 format.
	MaxTokenArgsLength = 65535
)

// NewV3ExtraArgs encodes v3 extra args params.
func NewV3ExtraArgs(finalityConfig uint16, gasLimit uint32, execAddr string, execArgs, tokenArgs []byte, ccvs []protocol.CCV) ([]byte, error) {
	// Manual encoding to match GenericExtraArgsV3 compact binary format
	// Format (from ExtraArgsCodec.sol):
	// - tag (4 bytes): 0x302326cb
	// - gasLimit (4 bytes): uint32
	// - blockConfirmations (2 bytes): uint16
	// - ccvsLength (1 byte): uint8
	// For each CCV (repeated ccvsLength times):
	//   - ccvAddressLength (1 byte): uint8 (0 or 20)
	//   - ccvAddress (variable): bytes (20 bytes if non-zero)
	//   - ccvArgsLength (2 bytes): uint16
	//   - ccvArgs (variable): bytes
	// - executorLength (1 byte): uint8 (0 or 20)
	// - executor (variable): bytes (20 bytes if non-zero)
	// - executorArgsLength (2 bytes): uint16
	// - executorArgs (variable): bytes
	// - tokenReceiverLength (1 byte): uint8 (0 or 20)
	// - tokenReceiver (variable): bytes (20 bytes if non-zero)
	// - tokenArgsLength (2 bytes): uint16
	// - tokenArgs (variable): bytes

	buf := new(bytes.Buffer)

	// Write tag
	buf.Write(GenericExtraArgsV3Tag)

	// Write gasLimit (uint32, big-endian)
	binary.Write(buf, binary.BigEndian, gasLimit)

	// Write blockConfirmations (uint16, big-endian)
	binary.Write(buf, binary.BigEndian, finalityConfig)

	// Write ccvsLength (uint8)
	if len(ccvs) > MaxCCVsPerMessage {
		return nil, fmt.Errorf("too many CCVs: %d (max %d)", len(ccvs), MaxCCVsPerMessage)
	}
	buf.WriteByte(uint8(len(ccvs)))

	// Write each CCV
	for i, ccv := range ccvs {
		ccvAddr := common.BytesToAddress(ccv.CCVAddress)
		isZeroAddr := ccvAddr == (common.Address{})

		if isZeroAddr {
			// Write ccvAddressLength = 0
			buf.WriteByte(0)
		} else {
			// Write ccvAddressLength = EVMAddressLength
			buf.WriteByte(EVMAddressLength)
			// Write ccvAddress (20 bytes)
			buf.Write(ccvAddr.Bytes())
		}

		// Write ccvArgsLength (uint16, big-endian)
		if len(ccv.Args) > MaxCCVArgsLength {
			return nil, fmt.Errorf("CCV[%d] args too long: %d bytes (max %d)", i, len(ccv.Args), MaxCCVArgsLength)
		}
		binary.Write(buf, binary.BigEndian, uint16(len(ccv.Args)))

		// Write ccvArgs
		buf.Write(ccv.Args)
	}

	// Write executor
	execAddress := common.HexToAddress(execAddr)
	isZeroExec := execAddress == (common.Address{})

	if isZeroExec {
		// Write executorLength = 0
		buf.WriteByte(0)
	} else {
		// Write executorLength = EVMAddressLength
		buf.WriteByte(EVMAddressLength)
		// Write executor (20 bytes)
		buf.Write(execAddress.Bytes())
	}

	// Write executorArgsLength (uint16, big-endian)
	if len(execArgs) > MaxExecutorArgsLength {
		return nil, fmt.Errorf("executor args too long: %d bytes (max %d)", len(execArgs), MaxExecutorArgsLength)
	}
	binary.Write(buf, binary.BigEndian, uint16(len(execArgs)))

	// Write executorArgs
	buf.Write(execArgs)

	// Write tokenReceiver (always empty for now)
	// Write tokenReceiverLength = 0
	buf.WriteByte(0)

	// Write tokenArgsLength (uint16, big-endian)
	if len(tokenArgs) > MaxTokenArgsLength {
		return nil, fmt.Errorf("token args too long: %d bytes (max %d)", len(tokenArgs), MaxTokenArgsLength)
	}
	binary.Write(buf, binary.BigEndian, uint16(len(tokenArgs)))

	// Write tokenArgs
	buf.Write(tokenArgs)

	return buf.Bytes(), nil
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
				// FeeUSDCents        uint16
				// PayloadSizeBytes   uint32
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
