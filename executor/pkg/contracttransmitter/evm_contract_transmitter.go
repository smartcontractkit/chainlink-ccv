package contracttransmitter

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	ccvagg "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	exectypes "github.com/smartcontractkit/chainlink-ccv/executor/types"
)

type EVMContractTransmitter struct {
	ctx           context.Context
	lggr          logger.Logger
	TxmClient     txmgr.TxManager
	TransactOpts  *bind.TransactOpts
	Client        *ethclient.Client
	Pk            *ecdsa.PrivateKey
	CcvAggregator ccvagg.CCVAggregator
	chainSelector uint64
	mu            sync.Mutex
}

func NewEVMContractTransmitterFromTxm(lggr logger.Logger, chainSelector uint64, client txmgr.TxManager) *EVMContractTransmitter {
	return &EVMContractTransmitter{
		lggr:          lggr,
		chainSelector: chainSelector,
		TxmClient:     client,
	}
}

// todo: this is a stub before we use real txm
func NewEVMContractTransmitterFromRPC(ctx context.Context, lggr logger.Logger, chainSelector uint64, rpc, privatekey string, ccvAggregatorAddress common.Address) (*EVMContractTransmitter, error) {
	// create a client for the ccv aggregator contract
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, err
	}

	pk, err := crypto.HexToECDSA(privatekey)
	if err != nil {
		return nil, err
	}

	id, err := chainselectors.GetChainIDFromSelector(chainSelector)
	if err != nil {
		return nil, err
	}
	chainIDInt := big.NewInt(0)
	chainIDInt.SetString(id, 10)

	auth := bind.NewKeyedTransactor(pk, chainIDInt)
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(300000) // in units

	boundContract, err := ccvagg.NewCCVAggregator(ccvAggregatorAddress, client)
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
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

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
	auth.Nonce = big.NewInt(int64(nonce)) //nolint:gosec // G115 will replace with txm
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

	encodedMsg, _ := report.Message.Encode()

	tx, err := ct.CcvAggregator.Execute(opts, encodedMsg, contractCcvs, report.CCVData)
	if err != nil {
		return err
	}

	ct.lggr.Infow("submitted tx to chain", "tx hash", tx.Hash().Hex())

	return nil
}
