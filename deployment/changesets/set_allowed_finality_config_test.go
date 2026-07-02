package changesets

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

func TestSetAllowedFinalityConfig_Validation_MissingQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := SetAllowedFinalityConfig()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), SetAllowedFinalityConfigInput{
		ChainSelectors: []uint64{sel},
	})
	require.ErrorContains(t, err, "committee qualifier is required")
}

func TestSetAllowedFinalityConfig_Validation_NoSelectors(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := SetAllowedFinalityConfig()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{chainsel.TEST_90000001.Selector}), SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
	})
	require.ErrorContains(t, err, "at least one chain selector is required")
}

func TestSetAllowedFinalityConfig_Validation_SelectorNotInEnv(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := SetAllowedFinalityConfig()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1}), SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel2},
	})
	require.ErrorContains(t, err, "is not available in environment")
}

func TestSetAllowedFinalityConfig_Validation_NoFinalityMode(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := SetAllowedFinalityConfig()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel},
	})
	require.ErrorContains(t, err, "at least one finality mode must be set")
}

func TestSetAllowedFinalityConfig_Validation_HappyPath(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := SetAllowedFinalityConfig()
	require.NoError(t, cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel},
		WaitForSafe:        true,
		BlockDepth:         5,
	}))
}

func TestSetAllowedFinalityConfig_Apply(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	stub := &stubOnchainAdapter{}
	registerEVMOnchain(stub)
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
		Logger:      logger.Test(t),
	}
	_, err := SetAllowedFinalityConfig().Apply(env, SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel},
		WaitForSafe:        true,
		BlockDepth:         3,
	})
	require.NoError(t, err)
	require.Equal(t, 1, stub.finalityCalls)
}

func TestSetAllowedFinalityConfig_Apply_AdapterError(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{onchainOpErr: errors.New("boom")})
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
		Logger:      logger.Test(t),
	}
	_, err := SetAllowedFinalityConfig().Apply(env, SetAllowedFinalityConfigInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel},
	})
	require.ErrorContains(t, err, "SetAllowedFinalityConfig failed")
}
