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

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	chainselectors "github.com/smartcontractkit/chain-selectors"
)

var _ executor.ContractTransmitter = &EVMContractTransmitter{}

type EVMContractTransmitter struct {
	ctx           context.Context
	lggr          logger.Logger
	TransactOpts  *bind.TransactOpts
	Client        *ethclient.Client
	Pk            *ecdsa.PrivateKey
	OffRamp       offramp.OffRamp
	chainSelector protocol.ChainSelector
	mu            sync.Mutex
}

func NewEVMContractTransmitterFromRPC(ctx context.Context, lggr logger.Logger, chainSelector protocol.ChainSelector, rpc, privatekey string, offRampAddress common.Address) (*EVMContractTransmitter, error) {
	// create a client for the off ramp contract
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, err
	}

	pk, err := crypto.HexToECDSA(privatekey)
	if err != nil {
		return nil, err
	}

	id, err := chainselectors.GetChainIDFromSelector(uint64(chainSelector))
	if err != nil {
		return nil, err
	}
	chainIDInt := big.NewInt(0)
	chainIDInt.SetString(id, 10)

	auth := bind.NewKeyedTransactor(pk, chainIDInt)
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(300000) // in units

	boundContract, err := offramp.NewOffRamp(offRampAddress, client)
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
		OffRamp:       *boundContract,
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
	// TODO: Use a proper limit
	auth.GasLimit = uint64(10000000) // in units

	return auth, nil
}

func (ct *EVMContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report executor.AbstractAggregatedReport) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	contractCcvs := make([]common.Address, 0)
	for _, ccv := range report.CCVS {
		contractCcvs = append(contractCcvs, common.HexToAddress(ccv.String()))
	}
	opts, err := ct.GetTransactOpts()
	if err != nil {
		return err
	}

	encodedMsg, _ := report.Message.Encode()
	tx, err := ct.OffRamp.Execute(opts, encodedMsg, contractCcvs, report.CCVData)
	if err != nil {
		return err
	}

	ct.lggr.Infow("submitted tx to chain", "messageID", report.Message.MustMessageID(), "txHash", tx.Hash().Hex())

	return nil
}
