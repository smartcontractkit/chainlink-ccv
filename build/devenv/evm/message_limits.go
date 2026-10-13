package evm

import (
	"context"
	"fmt"
	"math"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/fee_quoter"
	feequoterwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// V3 send-path billing limits: the non-payload bytes the destination fee
// quoter's maxDataBytes budget bills on top of the user payload, and the
// execution gas a message of a given payload size needs to be executed on
// this chain.
//
// Implements the optional per-family capability interfaces from
// cciptestinterfaces; the asserts below make a missing method a compile
// error for the EVM family.

var (
	_ cciptestinterfaces.MessageOverheadProvider   = (*CCIP17EVM)(nil)
	_ cciptestinterfaces.ExecutionGasLimitProvider = (*CCIP17EVM)(nil)
)

// evmV3MessageOverheadBytes is the non-payload overhead billed inside the
// destination fee quoter's maxDataBytes budget for a message from this chain:
// the committee verifier payload (582), this family's MessageV1 codec base
// (143, MessageV1Codec.MESSAGE_V1_EVM_SOURCE_BASE_SIZE) and the two destination
// address fields — 2*20 for an EVM destination (765), 2*32 for a Stellar
// destination (789), so the value must cover the largest destination family's
// address length; the remainder is headroom for the executor args and future
// fields.
const evmV3MessageOverheadBytes = 800

// Execution gas sizing for the destination execute transaction (offRamp.execute):
// the EVM intrinsic cost of the exec tx calldata plus a margin for the
// offRamp's own processing of the message and its CCV proofs.
const (
	// evmExecTxIntrinsicBase is the EVM intrinsic transaction cost (21K).
	evmExecTxIntrinsicBase uint64 = 21_000
	// evmExecTxGasPerDataByte is the intrinsic cost per nonzero calldata byte
	// (16 gas). Zero bytes cost 4; the payloads tests send are nonzero ("a").
	// It matches DestGasPerPayloadByteBase in the devenv fee quoter override.
	evmExecTxGasPerDataByte uint64 = 16
	// evmExecTxCalldataFraming is the exec tx calldata that is not the message
	// data: the offRamp.execute ABI framing, CCV proofs, and the receiver and
	// executor addresses.
	evmExecTxCalldataFraming uint64 = 1_000
	// evmOffRampExecGasMargin is headroom for the offRamp's own execution of
	// the message beyond the tx's intrinsic cost.
	evmOffRampExecGasMargin uint64 = 500_000
)

// GetMessageOverheadBytes returns the non-payload bytes billed inside the
// destination fee quoter's maxDataBytes budget for a message from this chain.
func (m *CCIP17EVM) GetMessageOverheadBytes(_ context.Context, _ uint64) (uint32, error) {
	return evmV3MessageOverheadBytes, nil
}

// GetExecutionGasLimit returns the execution gas limit needed to execute on
// this chain a message from remoteChainSelector whose data field is dataLen
// bytes long. The result is clamped to the fee quoter's MaxPerMsgGasLimit for
// the remote; a failed cap lookup skips the clamp rather than failing the
// sizing.
func (m *CCIP17EVM) GetExecutionGasLimit(ctx context.Context, remoteChainSelector uint64, dataLen uint32) (uint32, error) {
	gas := evmExecTxIntrinsicBase +
		evmExecTxGasPerDataByte*(uint64(dataLen)+evmExecTxCalldataFraming) +
		evmOffRampExecGasMargin
	if maxPerMsg, err := m.feeQuoterMaxPerMsgGasLimit(ctx, remoteChainSelector); err != nil {
		m.logger.Debug().Err(err).Uint64("remote", remoteChainSelector).
			Msg("failed to read fee quoter MaxPerMsgGasLimit; skipping gas clamp")
	} else if gas > uint64(maxPerMsg) {
		gas = uint64(maxPerMsg)
	}
	if gas > math.MaxUint32 {
		gas = math.MaxUint32
	}
	return uint32(gas), nil
}

// feeQuoterMaxPerMsgGasLimit reads this chain's own fee quoter dest chain
// config for the remote and returns its MaxPerMsgGasLimit — the same lookup
// as GetMaxDataBytes (impl.go), which reads the exact storage that validates
// sends to the remote.
func (m *CCIP17EVM) feeQuoterMaxPerMsgGasLimit(ctx context.Context, remoteChainSelector uint64) (uint32, error) {
	feeQuoterRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(m.chain.ChainSelector(), datastore.ContractType(fee_quoter.ContractType), semver.MustParse(fee_quoter.Deploy.Version()), ""))
	if err != nil {
		return 0, fmt.Errorf("failed to get fee quoter address: %w", err)
	}
	fq, err := feequoterwrapper.NewFeeQuoter(common.HexToAddress(feeQuoterRef.Address), m.ethClient)
	if err != nil {
		return 0, fmt.Errorf("failed to new fee quoter contract: %w", err)
	}
	destChainConfig, err := fq.GetDestChainConfig(&bind.CallOpts{Context: ctx}, remoteChainSelector)
	if err != nil {
		return 0, fmt.Errorf("failed to get dest chain config: %w", err)
	}
	// A missing mapping entry returns a zeroed config (MaxPerMsgGasLimit 0);
	// refuse it the same way GetMaxDataBytes does.
	if !destChainConfig.IsEnabled {
		return 0, fmt.Errorf("dest chain config for %d is not enabled", remoteChainSelector)
	}
	return destChainConfig.MaxPerMsgGasLimit, nil
}
