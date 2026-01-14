package contracttransmitter

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
	txmgrcommon "github.com/smartcontractkit/chainlink-framework/chains/txmgr"
)

var (
	_          executor.ContractTransmitter = &TXMEVMContractTransmitter{}
	offrampABI                              = evmtypes.MustGetABI(offramp.OffRampABI)
)

type TXMEVMContractTransmitter struct {
	lggr           logger.Logger
	TxmClient      txmgr.TxManager
	keys           keys.RoundRobin
	fromAddresses  []common.Address
	OffRampAddress common.Address
	chainSelector  protocol.ChainSelector
}

func NewEVMContractTransmitterFromTxm(lggr logger.Logger, chainSelector protocol.ChainSelector, client txmgr.TxManager, offRampAddress common.Address, keys keys.RoundRobin, fromAddresses []common.Address) *TXMEVMContractTransmitter {
	return &TXMEVMContractTransmitter{
		lggr:           lggr,
		chainSelector:  chainSelector,
		OffRampAddress: offRampAddress,
		TxmClient:      client,
		keys:           keys,
		fromAddresses:  fromAddresses,
	}
}

func (ct *TXMEVMContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report executor.AbstractAggregatedReport) error {
	encodedMsg, _ := report.Message.Encode()
	contractCcvs := make([]common.Address, 0)
	for _, ccv := range report.CCVS {
		contractCcvs = append(contractCcvs, common.HexToAddress(ccv.String()))
	}

	payload, err := offrampABI.Pack("execute", encodedMsg, contractCcvs, report.CCVData, DefaultGasLimitOverride)
	if err != nil {
		ct.lggr.Errorw("failed to abi encode execute payload", "error", err)
		return err
	}
	roundRobinFromAddress, err := ct.keys.GetNextAddress(ctx, ct.fromAddresses...)
	if err != nil {
		return fmt.Errorf("skipping transmit, error getting round-robin from address: %w", err)
	}
	messageID, _ := report.Message.MessageID()

	// we don't want to use an idempotency key based on messageid in case the CCV Data changes in between resubmissions
	tx, err := ct.TxmClient.CreateTransaction(ctx, txmgr.TxRequest{
		FromAddress:    roundRobinFromAddress,
		ToAddress:      ct.OffRampAddress,
		EncodedPayload: payload,
		FeeLimit:       uint64(report.Message.ExecutionGasLimit),
		Strategy:       txmgrcommon.NewSendEveryStrategy(),
	})
	if err != nil {
		return fmt.Errorf("failed to create txm transaction: %w", err)
	}

	ct.lggr.Infow("submitted tx to txm", "messageID", messageID, "txm key", tx.IdempotencyKey)
	return nil
}
