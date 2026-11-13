package evm

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

type stubBalanceClient struct {
	client.Client
	amounts map[common.Address]*big.Int
}

func (s *stubBalanceClient) BalanceAt(_ context.Context, address common.Address, _ *big.Int) (*big.Int, error) {
	amount, ok := s.amounts[address]
	if !ok {
		return nil, errors.New("RPC unavailable")
	}
	return amount, nil
}

func TestAccessorTransmitterBalances(t *testing.T) {
	address1 := common.HexToAddress("0x1000000000000000000000000000000000000001")
	address2 := common.HexToAddress("0x2000000000000000000000000000000000000002")
	runtime := &stubChainRuntime{
		Client:      &stubBalanceClient{amounts: map[common.Address]*big.Int{address1: big.NewInt(12345)}},
		addresses:   []common.Address{address1, address2},
		transmitter: noopContractTransmitter{},
	}
	acc := newAccessor(
		logger.Test(t), protocol.ChainSelector(42), runtime, common.HexToAddress("0x1234"), "evm-key",
		nil, nil, nil, nil, nil, nil, withNativeDecimals(18),
	).(*accessor)
	require.NoError(t, acc.SetKeystore(context.Background(), nil))

	balances, err := acc.TransmitterBalances(context.Background())
	require.ErrorContains(t, err, address2.Hex())
	require.Len(t, balances, 1)
	require.Equal(t, "evm-key", balances[0].KeyName)
	require.Equal(t, address1.Hex(), balances[0].Address)
	require.Equal(t, "12345", balances[0].Amount.String())
	require.Equal(t, uint8(18), balances[0].NativeTokenDecimals)
	require.Equal(t, "evm-key", runtime.gotAddrKey)
}

func TestAccessorTransmitterBalancesHonorsZeroDecimals(t *testing.T) {
	address := common.HexToAddress("0x1000000000000000000000000000000000000001")
	runtime := &stubChainRuntime{
		Client:      &stubBalanceClient{amounts: map[common.Address]*big.Int{address: big.NewInt(42)}},
		addresses:   []common.Address{address},
		transmitter: noopContractTransmitter{},
	}
	acc := newAccessor(
		logger.Test(t), protocol.ChainSelector(42), runtime, common.HexToAddress("0x1234"), "evm-key",
		nil, nil, nil, nil, nil, nil, withNativeDecimals(0),
	).(*accessor)
	require.NoError(t, acc.SetKeystore(context.Background(), nil))

	balances, err := acc.TransmitterBalances(context.Background())
	require.NoError(t, err)
	require.Len(t, balances, 1)
	require.Equal(t, uint8(0), balances[0].NativeTokenDecimals)
}
