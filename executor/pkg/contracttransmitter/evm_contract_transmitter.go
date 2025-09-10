package contracttransmitter

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	selectors "github.com/smartcontractkit/chain-selectors"
	ccvAgg "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	exectypes "github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

type EVMContractTransmitter struct {
	ctx           context.Context
	lggr          logger.Logger
	chainSelector uint64
	TxmClient     txmgr.TxManager
	TransactOpts  *bind.TransactOpts
	Client        *ethclient.Client
	Pk            *ecdsa.PrivateKey
	CcvAggregator ccvAgg.CCVAggregator
	mu            sync.Mutex
}

func NewEVMContractTransmitterFromTxm(lggr logger.Logger, chainSelector uint64, client txmgr.TxManager) *EVMContractTransmitter {
	return &EVMContractTransmitter{
		lggr:          lggr,
		chainSelector: chainSelector,
		TxmClient:     client,
	}
}

func NewEVMContractTransmitterFromRPC(ctx context.Context, lggr logger.Logger, chainSelector uint64, rpc string, privatekey string, ccvAggregatorAddress common.Address) (*EVMContractTransmitter, error) {
	// create a client for the ccv aggregator contract
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, err
	}

	// pk, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	pk, err := crypto.HexToECDSA(privatekey)
	if err != nil {
		return nil, err
	}

	id, err := selectors.GetChainIDFromSelector(chainSelector)
	if err != nil {
		return nil, err
	}
	chainIdInt := big.NewInt(0)
	chainIdInt.SetString(id, 10)

	auth := bind.NewKeyedTransactor(pk, chainIdInt)
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(300000) // in units

	boundContract, err := ccvAgg.NewCCVAggregator(ccvAggregatorAddress, client)
	if err != nil {
		return nil, err
	}

	return &EVMContractTransmitter{
		ctx:           ctx,
		lggr:          lggr,
		chainSelector: chainSelector,
		TransactOpts:  auth,
		Client:        client,
		Pk:            pk,
		CcvAggregator: *boundContract,
	}, nil
}

func (ct *EVMContractTransmitter) GetTransactOpts() (*bind.TransactOpts, error) {

	publicKey := ct.Pk.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := ct.Client.PendingNonceAt(ct.ctx, fromAddress)
	if err != nil {
		return nil, err
	}

	gasPrice, err := ct.Client.SuggestGasPrice(ct.ctx)
	if err != nil {
		return nil, err
	}

	auth := ct.TransactOpts
	auth.Nonce = big.NewInt(int64(nonce))
	auth.GasPrice = gasPrice

	return auth, nil
}

func (ct *EVMContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report exectypes.AbstractAggregatedReport) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	contractCcvs := make([]common.Address, len(report.CCVS))
	for _, ccv := range report.CCVS {
		contractCcvs = append(contractCcvs, common.Address(ccv))
	}

	opts, err := ct.GetTransactOpts()
	if err != nil {
		return err
	}

	tx, err := ct.CcvAggregator.Execute(opts, ccvAgg.CCVAggregatorAggregatedReport{
		Message: ccvAgg.InternalAny2EVMMessage{
			Receiver: common.Address(report.Message.Receiver),
			Sender:   report.Message.Sender,
			Data:     report.Message.Data,
			Header: ccvAgg.InternalHeader{
				SourceChainSelector: uint64(report.Message.SourceChainSelector),
				DestChainSelector:   uint64(report.Message.DestChainSelector),
				SequenceNumber:      uint64(report.Message.SequenceNumber),
			},
		},
		Ccvs:    contractCcvs,
		CcvData: report.CCVData,
	})
	if err != nil {
		return err
	}

	ct.lggr.Infow("submitted tx to chain", "tx hash", tx.Hash().Hex())

	return nil
}
