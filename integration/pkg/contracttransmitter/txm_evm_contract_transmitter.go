package contracttransmitter

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
	txmgrcommon "github.com/smartcontractkit/chainlink-framework/chains/txmgr"
)

const (
	// Numerator and Denominator to compensate for EIP-150 forwarding.
	eip150ForwardingNumerator   = 64
	eip150ForwardingDenominator = 63
)

var (
	_          chainaccess.ContractTransmitter = &TXMEVMContractTransmitter{}
	offrampABI                                 = evmtypes.MustGetABI(offramp.OffRampABI)
)

type TXMEVMContractTransmitter struct {
	lggr           logger.Logger
	TxmClient      txmgr.TxManager
	keys           keys.RoundRobin
	fromAddresses  []common.Address
	OffRampAddress common.Address
	chainSelector  protocol.ChainSelector
	monitoring     executor.Monitoring
}

func NewEVMContractTransmitterFromTxm(lggr logger.Logger, chainSelector protocol.ChainSelector, client txmgr.TxManager, offRampAddress common.Address, keys keys.RoundRobin, fromAddresses []common.Address, monitoring executor.Monitoring) *TXMEVMContractTransmitter {
	return &TXMEVMContractTransmitter{
		lggr:           lggr,
		chainSelector:  chainSelector,
		OffRampAddress: offRampAddress,
		TxmClient:      client,
		keys:           keys,
		fromAddresses:  fromAddresses,
		monitoring:     monitoring,
	}
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
	feeLimit := uint64(report.Message.ExecutionGasLimit) +
		eip150ForwardingGasBuffer(report.Message.CcipReceiveGasLimit)

	// we don't want to use an idempotency key based on messageid in case the CCV Data changes in between resubmissions
	tx, err := ct.TxmClient.CreateTransaction(ctx, txmgr.TxRequest{
		FromAddress:    roundRobinFromAddress,
		ToAddress:      ct.OffRampAddress,
		EncodedPayload: payload,
		FeeLimit:       feeLimit,
		Strategy:       txmgrcommon.NewSendEveryStrategy(),
	})
	if err != nil {
		ct.monitoring.Metrics().IncrementUnrecoverableMessageFailure(ctx)
		return fmt.Errorf("failed to create txm transaction: %w", err)
	}

	ct.lggr.Infow("submitted tx to txm", "messageID", messageID, "txm key", tx.IdempotencyKey)
	return nil
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
