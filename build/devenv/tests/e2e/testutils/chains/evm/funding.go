package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
)

func TransferTokens(t *testing.T, env *deployment.Environment, sel uint64, token, receiver string, amount int64) {
	require.True(t, common.IsHexAddress(receiver), "receiver address is not a valid hex address: %s", receiver)
	require.True(t, common.IsHexAddress(token), "token address is not a valid hex address: %s", token)

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	tok, err := erc20.NewERC20(common.HexToAddress(token), chain.Client)
	require.NoError(t, err, "failed to create ERC20 instance for token %s on chain %d", token, sel)

	dec, err := tok.Decimals(&bind.CallOpts{Context: t.Context()})
	require.NoError(t, err, "failed to get decimals for token %s on chain %d", token, sel)

	amt := tokens.ScaleTokenAmount(big.NewInt(amount), dec)
	tx, err := tok.Transfer(chain.DeployerKey, common.HexToAddress(receiver), amt)
	require.NoError(t, err, "failed to transfer %d tokens from %s to %s on chain %d", amount, chain.DeployerKey.From.Hex(), receiver, sel)

	receipt, err := bind.WaitMined(t.Context(), chain.Client, tx.Hash())
	require.NoError(t, err, "failed to wait for transaction %s to be mined on chain %d", tx.Hash().Hex(), sel)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "transaction %s failed on chain %d", tx.Hash().Hex(), sel)
}
