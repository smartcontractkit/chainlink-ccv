package contracttransmitter

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	chainselectors "github.com/smartcontractkit/chain-selectors"
)

var _ chainaccess.ContractTransmitter = &KeystoreEVMContractTransmitter{}

// KeystoreEVMContractTransmitter submits OffRamp execute transactions using a
// keystore-managed secp256k1 key. Private key material never leaves the
// keystore; signing is delegated via the keystore's Sign method.
//
// This is the keystore-backed equivalent of [EVMContractTransmitter].
// The TxManager-backed [TXMEVMContractTransmitter] is preferred for production
// because it handles retries, gas bumping, and nonce management; this
// transmitter is suitable for simpler deployments or testing.
type KeystoreEVMContractTransmitter struct {
	lggr          logger.Logger
	ks            keystore.Keystore
	keyName       string
	addr          common.Address
	chainID       *big.Int
	Client        *ethclient.Client
	OffRamp       offramp.OffRamp
	chainSelector protocol.ChainSelector
	mu            sync.Mutex
}

// NewEVMContractTransmitterFromKeystore constructs a [KeystoreEVMContractTransmitter].
//
// keyName is the key name as stored in the keystore (plain name, no chain-family prefix).
// The keystore is queried directly using the name as-is, matching how the verifier
// accesses its signing key.
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

	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q from keystore: %w", keyName, err)
	}
	if len(keysResp.Keys) == 0 {
		return nil, fmt.Errorf("key %q not found in keystore", keyName)
	}

	keyInfo := keysResp.Keys[0].KeyInfo
	if keyInfo.KeyType != keystore.ECDSA_S256 {
		return nil, fmt.Errorf("key %q has unexpected type %s, expected %s", keyName, keyInfo.KeyType, keystore.ECDSA_S256)
	}

	publicKey, err := crypto.UnmarshalPubkey(keyInfo.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key for %q: %w", keyName, err)
	}
	addr := crypto.PubkeyToAddress(*publicKey)

	boundContract, err := offramp.NewOffRamp(offRampAddress, client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind OffRamp contract: %w", err)
	}

	return &KeystoreEVMContractTransmitter{
		lggr:          lggr,
		ks:            ks,
		keyName:       keyName,
		addr:          addr,
		chainID:       chainID,
		Client:        client,
		OffRamp:       *boundContract,
		chainSelector: chainSelector,
	}, nil
}

// GetTransactOpts builds [bind.TransactOpts] backed by the keystore key.
// Nonce and gas price are fetched live from the pending state.
func (ct *KeystoreEVMContractTransmitter) GetTransactOpts(ctx context.Context) (*bind.TransactOpts, error) {
	nonce, err := ct.Client.PendingNonceAt(ctx, ct.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pending nonce: %w", err)
	}

	gasPrice, err := ct.Client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	chainID := ct.chainID
	ks := ct.ks
	keyName := ct.keyName
	auth := &bind.TransactOpts{
		From: ct.addr,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if ct.addr != address {
				return nil, bind.ErrNotAuthorized
			}
			signer := types.LatestSignerForChainID(chainID)
			h := signer.Hash(tx)
			signResp, err := ks.Sign(ctx, keystore.SignRequest{
				KeyName: keyName,
				Data:    h[:],
			})
			if err != nil {
				return nil, fmt.Errorf("keystore sign failed: %w", err)
			}
			return tx.WithSignature(signer, signResp.Signature)
		},
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

	opts, err := ct.GetTransactOpts(ctx)
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
