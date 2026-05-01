package contracttransmitter

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"

	chainselectors "github.com/smartcontractkit/chain-selectors"
)

var _ chainaccess.ContractTransmitter = &KeystoreEVMContractTransmitter{}

// KeystoreEVMContractTransmitter submits OffRamp execute transactions using a
// keystore-managed secp256k1 key. Private key material never leaves the
// keystore; signing is delegated via [evmkeys.TxKey.GetTransactOpts].
//
// This is the keystore-backed equivalent of [EVMContractTransmitter].
// The TxManager-backed [TXMEVMContractTransmitter] is preferred for production
// because it handles retries, gas bumping, and nonce management; this
// transmitter is suitable for simpler deployments or testing.
type KeystoreEVMContractTransmitter struct {
	lggr          logger.Logger
	txKey         *evmkeys.TxKey
	chainID       *big.Int
	Client        *ethclient.Client
	OffRamp       offramp.OffRamp
	chainSelector protocol.ChainSelector
	mu            sync.Mutex
}

// NewEVMContractTransmitterFromKeystore constructs a [KeystoreEVMContractTransmitter].
//
// keyName must be the full keystore path (e.g. executor.DefaultEVMTransmitterKeyName
// which is "evm/tx/executor_evm_transmitter_key"). [evmkeys.GetTxKeys] is called with
// [evmkeys.WithNoPrefix] so the name is used as-is without an additional evm/tx/ prefix.
func NewEVMContractTransmitterFromKeystore(
	ctx context.Context,
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
	rpc string,
	ks keystore.Keystore,
	keyName string,
	offRampAddress common.Address,
) (*KeystoreEVMContractTransmitter, error) {
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC: %w", err)
	}

	id, err := chainselectors.GetChainIDFromSelector(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID for selector %d: %w", chainSelector, err)
	}
	chainID := new(big.Int)
	chainID.SetString(id, 10)

	txKeys, err := evmkeys.GetTxKeys(ctx, ks, []string{keyName}, evmkeys.WithNoPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to get tx key %q from keystore: %w", keyName, err)
	}
	if len(txKeys) == 0 {
		return nil, fmt.Errorf("key %q not found in keystore", keyName)
	}

	boundContract, err := offramp.NewOffRamp(offRampAddress, client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind OffRamp contract: %w", err)
	}

	return &KeystoreEVMContractTransmitter{
		lggr:          lggr,
		txKey:         txKeys[0],
		chainID:       chainID,
		Client:        client,
		OffRamp:       *boundContract,
		chainSelector: chainSelector,
	}, nil
}

// getTransactOpts builds [bind.TransactOpts] backed by the keystore key.
// Nonce and gas price are fetched live from the pending state.
func (ct *KeystoreEVMContractTransmitter) getTransactOpts(ctx context.Context) (*bind.TransactOpts, error) {
	nonce, err := ct.Client.PendingNonceAt(ctx, ct.txKey.Address())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pending nonce: %w", err)
	}

	gasPrice, err := ct.Client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	auth, err := ct.txKey.GetTransactOpts(ctx, ct.chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get transact opts from keystore key: %w", err)
	}

	auth.Nonce = big.NewInt(int64(nonce)) //nolint:gosec // G115 will replace with txm
	auth.GasPrice = gasPrice
	auth.GasLimit = uint64(10000000) // TODO: use a proper gas limit

	return auth, nil
}

func (ct *KeystoreEVMContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report protocol.AbstractAggregatedReport) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	encodedMsg, err := report.Message.Encode()
	if err != nil {
		ct.lggr.Errorw("unable to submit txn: invalid message encoding", "error", err, "messageID", report.Message.MustMessageID())
		return errors.Join(executor.ErrMessageEncoding, fmt.Errorf("unable to submit txn: invalid message encoding: %w", err))
	}

	contractCcvs := make([]common.Address, 0, len(report.CCVS))
	for _, ccv := range report.CCVS {
		contractCcvs = append(contractCcvs, common.HexToAddress(ccv.String()))
	}

	opts, err := ct.getTransactOpts(ctx)
	if err != nil {
		return err
	}

	tx, err := ct.OffRamp.Execute(opts, encodedMsg, contractCcvs, report.CCVData, DefaultGasLimitOverride)
	if err != nil {
		return fmt.Errorf("OffRamp.Execute failed: %w", err)
	}

	ct.lggr.Infow("submitted tx to chain", "messageID", report.Message.MustMessageID(), "txHash", tx.Hash().Hex())
	return nil
}
