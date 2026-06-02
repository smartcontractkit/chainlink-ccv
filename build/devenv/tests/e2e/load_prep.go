package e2e

import (
	"context"
	"math/big"
	"strconv"
	"testing"

	"github.com/Masterminds/semver/v3"
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

// EnsureWETHBalanceAndApproval funds deployer keys and approves the CCIP router for load tests.
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
	require.NoError(t, err)

	wethInstance, err := weth9.NewWETH9(common.HexToAddress(wethContract.Address), chain.Client)
	require.NoError(t, err)

	routerInstance, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		chain.Selector,
		datastore.ContractType(router.ContractType),
		semver.MustParse(router.Deploy.Version()),
		""))
	require.NoError(t, err)

	for _, user := range chain.Users {
		wethBalance, err := wethInstance.BalanceOf(nil, user.From)
		require.NoError(t, err)

		if wethBalance.Cmp(requiredWETH) < 0 {
			depositAmount := new(big.Int).Sub(requiredWETH, wethBalance)
			oldValue := user.Value
			user.Value = depositAmount
			tx1, err := wethInstance.Deposit(user)
			require.NoError(t, err)
			_, err = chain.Confirm(tx1)
			require.NoError(t, err)
			user.Value = oldValue
		}

		tx, err := wethInstance.Approve(user, common.HexToAddress(routerInstance.Address), requiredWETH)
		require.NoError(t, err)
		_, err = chain.Confirm(tx)
		require.NoError(t, err)
	}
}
