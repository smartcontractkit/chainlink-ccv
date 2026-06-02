package e2e

import (
	"context"
	"math/big"
	"strconv"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/weth9"
)

const requiredWETHBalanceForLoad = 1e18

// EnsureWETHBalanceAndApproval prepares WETH and router approval for CCIP load senders on chain.Users.
func EnsureWETHBalanceAndApproval(ctx context.Context, t *testing.T, logger zerolog.Logger, e *deployment.Environment, chain cldfevm.Chain) {
	t.Helper()

	requiredWETH := big.NewInt(requiredWETHBalanceForLoad)

	logger.Info().Str("chain", strconv.FormatUint(chain.Selector, 10)).Msg("Ensuring WETH balance and approval")
	wethContract, err := e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			chain.Selector,
			datastore.ContractType(weth.ContractType),
			semver.MustParse(weth.Deploy.Version()),
			""))
	require.NoErrorf(t, err, "failed to resolve WETH contract for chain %d", chain.Selector)

	wethInstance, err := weth9.NewWETH9(common.HexToAddress(wethContract.Address), chain.Client)
	require.NoErrorf(t, err, "failed to bind WETH contract %s for chain %d", wethContract.Address, chain.Selector)

	routerInstance, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		chain.Selector,
		datastore.ContractType(router.ContractType),
		semver.MustParse(router.Deploy.Version()),
		""))
	require.NoErrorf(t, err, "failed to resolve router contract for chain %d", chain.Selector)

	routerAddr := common.HexToAddress(routerInstance.Address)
	funded := make(map[common.Address]struct{}, len(chain.Users)+1)

	for _, user := range chain.Users {
		ensureUserWETHBalanceAndApproval(ctx, t, logger, chain, wethInstance, routerAddr, user, requiredWETH)
		funded[user.From] = struct{}{}
	}

	// SendChainMessage pre-checks DeployerKey, not the round-robin sender.
	if _, ok := funded[chain.DeployerKey.From]; !ok {
		ensureUserWETHBalanceAndApproval(ctx, t, logger, chain, wethInstance, routerAddr, chain.DeployerKey, requiredWETH)
	}
}

// ensureUserWETHBalanceAndApproval makes one signing key ready to pay CCIP load fees in WETH.
func ensureUserWETHBalanceAndApproval(
	ctx context.Context,
	t *testing.T,
	logger zerolog.Logger,
	chain cldfevm.Chain,
	wethInstance *weth9.WETH9,
	routerAddr common.Address,
	user *bind.TransactOpts,
	requiredWETH *big.Int,
) {
	t.Helper()

	logger.Info().Str("user", user.From.String()).Msg("User address")
	balance, err := chain.Client.BalanceAt(ctx, user.From, nil)
	require.NoErrorf(t, err, "failed to read native balance for user %s on chain %d", user.From.String(), chain.Selector)
	logger.Info().Str("balance", balance.String()).Msg("User native balance before deposit")

	wethBalance, err := wethInstance.BalanceOf(nil, user.From)
	require.NoErrorf(t, err, "failed to read WETH balance for user %s on chain %d", user.From.String(), chain.Selector)
	logger.Info().
		Str("wethBalance", wethBalance.String()).
		Str("requiredWETH", requiredWETH.String()).
		Msg("User WETH balance before deposit")

	if wethBalance.Cmp(requiredWETH) < 0 {
		depositAmount := new(big.Int).Sub(requiredWETH, wethBalance)
		oldValue := user.Value
		user.Value = depositAmount
		// WETH deposit sends native ETH via msg.Value; restore so later txs do not inherit it.
		defer func() { user.Value = oldValue }()
		tx1, err := wethInstance.Deposit(user)
		require.NoErrorf(t, err, "failed to deposit WETH for user %s on chain %d", user.From.String(), chain.Selector)
		_, err = chain.Confirm(tx1)
		require.NoErrorf(t, err, "failed to confirm WETH deposit tx %s for user %s on chain %d", tx1.Hash().Hex(), user.From.String(), chain.Selector)
		logger.Info().Str("depositAmount", depositAmount.String()).Msg("Deposited WETH")
	}

	tx, err := wethInstance.Approve(user, routerAddr, requiredWETH)
	require.NoErrorf(t, err, "failed to approve router %s for user %s on chain %d", routerAddr.Hex(), user.From.String(), chain.Selector)
	_, err = chain.Confirm(tx)
	require.NoErrorf(t, err, "failed to confirm approve tx %s for user %s on chain %d", tx.Hash().Hex(), user.From.String(), chain.Selector)
	logger.Info().Str("approvedAmount", requiredWETH.String()).Msg("Approved WETH for router")
}
