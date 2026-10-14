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

// Ensure EVM exposes its V3 message-overhead and gas-limit capabilities.

var (
	_ cciptestinterfaces.MessageOverheadProvider   = (*CCIP17EVM)(nil)
	_ cciptestinterfaces.ExecutionGasLimitProvider = (*CCIP17EVM)(nil)
)

// evmV3MessageOverheadBytes is the non-payload overhead billed inside the
// dest fee quoter's maxDataBytes budget for a data-only message from this
// chain: 582 CV payload + 143 codec base + 2*32 dest addrs (largest family).
const evmV3MessageOverheadBytes = 789

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
	// evmOnRampGasReserve is the gas the OnRamp adds to gasLimitSum on top of
	// the extra-args value: the dest chain config's baseExecutionGasCost 150_000
	// plus each CCV's gasForVerification for 500_000.
	evmOnRampGasReserve uint64 = 650_000
)

// GetMessageOverheadBytes returns the non-payload bytes billed inside the
// destination fee quoter's maxDataBytes budget for a message from this chain.
func (m *CCIP17EVM) GetMessageOverheadBytes(_ context.Context, _ uint64) (uint32, error) {
	return evmV3MessageOverheadBytes, nil
}

// GetExecutionGasLimit returns the execution gas limit for the extra args of
// a message from remoteChainSelector whose data field is dataLen bytes long.
func (m *CCIP17EVM) GetExecutionGasLimit(ctx context.Context, remoteChainSelector uint64, dataLen uint32) (uint32, error) {
	gas := evmExecTxIntrinsicBase +
		evmExecTxGasPerDataByte*(uint64(dataLen)+evmExecTxCalldataFraming) +
		evmOffRampExecGasMargin
	if cfg, err := m.feeQuoterDestChainConfig(ctx, remoteChainSelector); err != nil {
		m.logger.Debug().Err(err).Uint64("remote", remoteChainSelector).
			Msg("failed to read fee quoter dest chain config; skipping gas clamp")
	} else {
		// calldataGas uses bytesOverheadSum, which the overhead constant
		// approximates for a data-only message (it covers the largest
		// destination family's address length).
		calldataGas := uint64(cfg.DestGasPerPayloadByteBase) * (uint64(dataLen) + evmV3MessageOverheadBytes)
		reserve := evmOnRampGasReserve + calldataGas
		// maxPerMsg <= reserve: the cap cannot even fit the OnRamp's own
		// terms, so leave the value unclamped and let the send revert
		// loudly instead of silently undersizing.
		if maxPerMsg := uint64(cfg.MaxPerMsgGasLimit); maxPerMsg > reserve && gas > maxPerMsg-reserve {
			gas = maxPerMsg - reserve
		}
	}
	if gas > math.MaxUint32 {
		gas = math.MaxUint32
	}
	return uint32(gas), nil
}

// feeQuoterDestChainConfig reads this chain's own fee quoter dest chain
// config for the remote — the same lookup as GetMaxDataBytes (impl.go), which
// reads the exact storage that validates sends to the remote.
func (m *CCIP17EVM) feeQuoterDestChainConfig(ctx context.Context, remoteChainSelector uint64) (feequoterwrapper.FeeQuoterDestChainConfig, error) {
	feeQuoterRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(m.chain.ChainSelector(), datastore.ContractType(fee_quoter.ContractType), semver.MustParse(fee_quoter.Deploy.Version()), ""))
	if err != nil {
		return feequoterwrapper.FeeQuoterDestChainConfig{}, fmt.Errorf("failed to get fee quoter address: %w", err)
	}
	fq, err := feequoterwrapper.NewFeeQuoter(common.HexToAddress(feeQuoterRef.Address), m.ethClient)
	if err != nil {
		return feequoterwrapper.FeeQuoterDestChainConfig{}, fmt.Errorf("failed to new fee quoter contract: %w", err)
	}
	destChainConfig, err := fq.GetDestChainConfig(&bind.CallOpts{Context: ctx}, remoteChainSelector)
	if err != nil {
		return feequoterwrapper.FeeQuoterDestChainConfig{}, fmt.Errorf("failed to get dest chain config: %w", err)
	}
	// A missing mapping entry returns a zeroed config; refuse it the same
	// way GetMaxDataBytes does.
	if !destChainConfig.IsEnabled {
		return feequoterwrapper.FeeQuoterDestChainConfig{}, fmt.Errorf("dest chain config for %d is not enabled", remoteChainSelector)
	}
	return destChainConfig, nil
}
