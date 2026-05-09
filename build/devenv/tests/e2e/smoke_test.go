package e2e

import (
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	burn_mint_erc20_with_drip_v1_5 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
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

	_, env, err := ccv.NewCLDFOperationsEnvironment(cfg.Blockchains, cfg.CLDF.DataStore)
	require.NoError(t, err)

	sels, err := FirstTwoEVMSelectors(cfg)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(sels), 2, "expected at least 2 EVM chains for this test in the environment")
	srcSel, dstSel := sels[0], sels[1]

	aggregators, err := ccv.NewAggregatorClientsFromCfg(ctx, cfg)
	require.NoError(t, err)
	mon, err := ccv.FirstIndexerMonitorFromEndpoints(ctx, cfg.IndexerEndpoints, ccv.Plog)
	require.NoError(t, err)

	caseOpts := []tcapi.CaseOption{
		tcapi.WithLane(srcSel, dstSel),
		tcapi.WithAggregatorClients(aggregators),
		tcapi.WithIndexerMonitor(mon),
	}

	t.Run("extra args v3 messaging", func(t *testing.T) {
		cases, err := basic.All(ctx, env, caseOpts...)
		require.NoError(t, err)
		for _, tc := range cases {
			if tc.HavePrerequisites(ctx) {
				t.Run(tc.Name(), func(t *testing.T) {
					subtestCtx := ccv.Plog.WithContext(t.Context())
					require.NoError(t, tc.Run(subtestCtx))
				})
			} else {
				t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
			}
		}
	})

	t.Run("extra args v3 token transfer", func(t *testing.T) {
		combos := common.AllTokenCombinations()
		cases, err := token_transfer.All(ctx, env, combos, caseOpts...)
		require.NoError(t, err)
		for _, tc := range cases {
			if tc.HavePrerequisites(ctx) {
				t.Run(tc.Name(), func(t *testing.T) {
					subtestCtx := ccv.Plog.WithContext(t.Context())
					require.NoError(t, tc.Run(subtestCtx))
				})
			} else {
				t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
			}
		}
		cases17, err := token_transfer.All17(ctx, env, combos, caseOpts...)
		require.NoError(t, err)
		for _, tc := range cases17 {
			if tc.HavePrerequisites(ctx) {
				t.Run(tc.Name(), func(t *testing.T) {
					subtestCtx := ccv.Plog.WithContext(t.Context())
					require.NoError(t, tc.Run(subtestCtx))
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

func getUSDCTokenAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64) protocol.UnknownAddress {
	return getContractAddress(t, ccvCfg, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip_v1_5.ContractType),
		burn_mint_erc20_with_drip_v1_5.Deploy.Version(),
		"",
		"USDC")
}

func getLombardTokenAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64) protocol.UnknownAddress {
	return getContractAddress(t, ccvCfg, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip_v1_5.ContractType),
		burn_mint_erc20_with_drip_v1_5.Deploy.Version(),
		common.LombardContractsQualifier,
		"Lombard token")
}
