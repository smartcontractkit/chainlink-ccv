package e2e

import (
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/token_transfer"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const (
	defaultExecTimeout = 40 * time.Second
	defaultSentTimeout = 10 * time.Second
)

func TestE2ESmoke_Basic(t *testing.T) {
	cfg, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())

	harness, err := tcapi.NewTestHarness(
		ctx,
		GetSmokeTestConfig(),
		cfg,
		chain_selectors.FamilyEVM,
	)
	require.NoError(t, err)

	chains, err := harness.Lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	src, dest := chains[0].CCIP17, chains[1].CCIP17

	t.Run("extra args v3 messaging", func(t *testing.T) {
		for _, tc := range basic.All(src, dest) {
			if tc.HavePrerequisites(ctx, cfg) {
				t.Run(tc.Name(), func(t *testing.T) {
					require.NoError(t, tc.Run(ctx, harness, cfg))
				})
			} else {
				t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
			}
		}
	})

	t.Run("extra args v3 token transfer", func(t *testing.T) {
		for _, tc := range token_transfer.All(src, dest) {
			if tc.HavePrerequisites(ctx, cfg) {
				t.Run(tc.Name(), func(t *testing.T) {
					require.NoError(t, tc.Run(ctx, harness, cfg))
				})
			} else {
				t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
			}
		}
		for _, tc := range token_transfer.All17(src, dest) {
			if tc.HavePrerequisites(ctx, cfg) {
				t.Run(tc.Name(), func(t *testing.T) {
					require.NoError(t, tc.Run(ctx, harness, cfg))
				})
			} else {
				t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
			}
		}
	})
}

func mustGetEOAReceiverAddress(t *testing.T, c cciptestinterfaces.CCIP17) protocol.UnknownAddress {
	receiver, err := c.GetEOAReceiverAddress()
	require.NoError(t, err)
	return receiver
}

func mustGetSenderAddress(t *testing.T, c cciptestinterfaces.CCIP17) protocol.UnknownAddress {
	sender, err := c.GetSenderAddress()
	require.NoError(t, err)
	return sender
}

func getContractAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) protocol.UnknownAddress {
	ref, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	require.NoErrorf(t, err, "failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s",
		contractName, chainSelector, contractType, version)
	return protocol.UnknownAddress(gethcommon.HexToAddress(ref.Address).Bytes())
}

func getTokenAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, qualifier string) protocol.UnknownAddress {
	return getContractAddress(t, ccvCfg, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
		burn_mint_erc20_with_drip.Deploy.Version(),
		qualifier,
		"burn mint erc677")
}
