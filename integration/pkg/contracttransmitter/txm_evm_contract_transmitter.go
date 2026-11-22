package contracttransmitter

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
	"github.com/smartcontractkit/chainlink-framework/chains/fees"
	txmgrcommon "github.com/smartcontractkit/chainlink-framework/chains/txmgr"
)

const (
	// DefaultKeyName is the full keystore path of the ECDSA key the executor
	// uses to sign and submit OffRamp transactions on EVM chains.
	DefaultKeyName = "evm/tx/executor_evm_transmitter_key"

	// Numerator and Denominator to compensate for EIP-150 forwarding.
	eip150ForwardingNumerator   = 64
	eip150ForwardingDenominator = 63
	executionGasEstimateBuffer  = float32(1.15)
)

// GasEstimator estimates the complete transaction cost, including calldata and contract execution.
type GasEstimator interface {
	// EstimateGas returns the gas required by the complete transaction.
	EstimateGas(context.Context, ethereum.CallMsg) (uint64, error)
}

// TransmitterOption customizes a TXMEVMContractTransmitter.
type TransmitterOption func(*TXMEVMContractTransmitter)

// WithGasEstimator enables full transaction estimation before TXM creates an attempt.
func WithGasEstimator(estimator GasEstimator) TransmitterOption {
	return func(ct *TXMEVMContractTransmitter) {
		ct.gasEstimator = estimator
	}
}

var (
	_          chainaccess.ContractTransmitter      = &TXMEVMContractTransmitter{}
	_          chainaccess.ExecutorMonitoringSetter = &TXMEVMContractTransmitter{}
	offrampABI                                      = evmtypes.MustGetABI(offramp.OffRampABI)
)

type TXMEVMContractTransmitter struct {
	lggr           logger.Logger
	TxmClient      txmgr.TxManager
	keys           keys.RoundRobin
	fromAddresses  []common.Address
	OffRampAddress common.Address
	chainSelector  protocol.ChainSelector
	gasEstimator   GasEstimator
	monitoring     monitoring.Monitoring
}

func NewEVMContractTransmitterFromTxm(lggr logger.Logger, chainSelector protocol.ChainSelector, client txmgr.TxManager, offRampAddress common.Address, keys keys.RoundRobin, fromAddresses []common.Address, monitoring monitoring.Monitoring, opts ...TransmitterOption) *TXMEVMContractTransmitter {
	ct := &TXMEVMContractTransmitter{
		lggr:           lggr,
		chainSelector:  chainSelector,
		OffRampAddress: offRampAddress,
		TxmClient:      client,
		keys:           keys,
		fromAddresses:  fromAddresses,
		monitoring:     monitoring,
	}
	for _, opt := range opts {
		opt(ct)
	}
	return ct
}

// SetExecutorMonitoring implements chainaccess.ExecutorMonitoringSetter. The accessor builds the
// transmitter with no-op monitoring because the executor's process-level monitoring does not
// exist yet; the executor swaps in the real one here before the coordinator starts.
func (ct *TXMEVMContractTransmitter) SetExecutorMonitoring(m monitoring.Monitoring) {
	if m == nil {
		return
	}
	ct.monitoring = m
}

func (ct *TXMEVMContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report protocol.AbstractAggregatedReport) error {
	encodedMsg, err := report.Message.Encode()
	if err != nil {
		ct.lggr.Errorw("unable to submit txn: invalid message encoding", "error", err, "messageID", report.Message.MustMessageID())
		ct.monitoring.Metrics().IncrementUnrecoverableMessageFailure(ctx)
		return errors.Join(executor.ErrMessageEncoding, fmt.Errorf("unable to submit txn: invalid message encoding %s", err))
	}

	contractCcvs := make([]common.Address, 0)
	for _, ccv := range report.CCVS {
		contractCcvs = append(contractCcvs, common.HexToAddress(ccv.String()))
	}

	payload, err := offrampABI.Pack("execute", encodedMsg, contractCcvs, report.CCVData, DefaultGasLimitOverride)
	if err != nil {
		ct.lggr.Errorw("failed to abi encode execute payload", "error", err)
		ct.monitoring.Metrics().IncrementUnrecoverableMessageFailure(ctx)
		return err
	}
	roundRobinFromAddress, err := ct.keys.GetNextAddress(ctx, ct.fromAddresses...)
	if err != nil {
		return fmt.Errorf("skipping transmit, error getting round-robin from address: %w", err)
	}
	messageID, _ := report.Message.MessageID()
	messageGasLimit := uint64(report.Message.ExecutionGasLimit) +
		eip150ForwardingGasBuffer(report.Message.CcipReceiveGasLimit)
	gasLimit, err := ct.estimateGasLimit(ctx, roundRobinFromAddress, payload, messageGasLimit)
	if err != nil {
		return fmt.Errorf("failed to estimate execution gas for message %s: %w", messageID, err)
	}

	// we don't want to use an idempotency key based on messageid in case the CCV Data changes in between resubmissions
	tx, err := ct.TxmClient.CreateTransaction(ctx, txmgr.TxRequest{
		FromAddress:    roundRobinFromAddress,
		ToAddress:      ct.OffRampAddress,
		EncodedPayload: payload,
		FeeLimit:       gasLimit,
		Strategy:       txmgrcommon.NewSendEveryStrategy(),
		// Correlates this tx with its CCIP message in TXM logs (the TXM
		// logs meta.MessageIDs as "messageID" on every tx log line).
		Meta: &txmgr.TxMeta{
			MessageIDs: []string{messageID.String()},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create txm transaction: %w", err)
	}

	ct.lggr.Infow("submitted tx to txm", "messageID", messageID, "txm key", tx.IdempotencyKey, "gasLimit", gasLimit, "messageGasLimit", messageGasLimit)
	return nil
}

func (ct *TXMEVMContractTransmitter) estimateGasLimit(ctx context.Context, from common.Address, payload []byte, messageGasLimit uint64) (uint64, error) {
	if ct.gasEstimator == nil {
		return 0, errors.New("EVM gas estimator is not configured")
	}
	estimatedGas, err := ct.gasEstimator.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &ct.OffRampAddress, Data: payload})
	if err != nil {
		return 0, err
	}
	if estimatedGas == 0 {
		return 0, errors.New("EVM gas estimator returned zero")
	}
	if estimatedGas <= messageGasLimit {
		return messageGasLimit, nil
	}
	buffered, err := fees.ApplyMultiplier(estimatedGas, executionGasEstimateBuffer)
	if err != nil {
		return 0, fmt.Errorf("failed to buffer gas estimate %d: %w", estimatedGas, err)
	}
	return max(messageGasLimit, buffered), nil
}

// eip150ForwardingGasBuffer returns the extra gas needed to compensate for EIP-150
// gas attenuation across the OffRamp -> Router -> Receiver call path.
// It computes ceil(64/63 * ceil(64/63 * L)) - L, where L is the ccipReceive gas limit.
func eip150ForwardingGasBuffer(ccipReceiveGasLimit uint32) uint64 {
	gasLimit := uint64(ccipReceiveGasLimit)
	// Gas required at Router for Receiver to get L: ceil(64/63 * L)
	atRouter := (eip150ForwardingNumerator*gasLimit +
		eip150ForwardingDenominator - 1) / eip150ForwardingDenominator
	// Gas required at OffRamp for Router to get atRouter: ceil(64/63 * atRouter)
	atOffRamp := (eip150ForwardingNumerator*atRouter +
		eip150ForwardingDenominator - 1) / eip150ForwardingDenominator
	// Buffer is the extra gas on top of L
	return atOffRamp - gasLimit
}
