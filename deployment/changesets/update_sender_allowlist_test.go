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

func TestUpdateSenderAllowlist_Validation_MissingQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := UpdateSenderAllowlist()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), UpdateSenderAllowlistInput{
		ChainSelectors:    []uint64{sel},
		DestChainSelector: chainsel.TEST_90000002.Selector,
	})
	require.ErrorContains(t, err, "committee qualifier is required")
}

func TestUpdateSenderAllowlist_Validation_NoSelectors(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := UpdateSenderAllowlist()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{chainsel.TEST_90000001.Selector}), UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		DestChainSelector:  chainsel.TEST_90000002.Selector,
	})
	require.ErrorContains(t, err, "at least one chain selector is required")
}

func TestUpdateSenderAllowlist_Validation_MissingDestChain(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := UpdateSenderAllowlist()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel},
	})
	require.ErrorContains(t, err, "destination chain selector is required")
}

func TestUpdateSenderAllowlist_Validation_SelectorNotInEnv(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := UpdateSenderAllowlist()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1}), UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel2},
		DestChainSelector:  sel1,
	})
	require.ErrorContains(t, err, "is not available in environment")
}

func TestUpdateSenderAllowlist_Validation_HappyPath(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := UpdateSenderAllowlist()
	require.NoError(t, cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1}), UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel1},
		DestChainSelector:  sel2,
		AllowlistEnabled:   true,
		AddedSenders:       []string{"0x000000000000000000000000000000000000aBcD"},
	}))
}

func TestUpdateSenderAllowlist_Apply(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	stub := &stubOnchainAdapter{}
	registerEVMOnchain(stub)
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
		Logger:      logger.Test(t),
	}
	_, err := UpdateSenderAllowlist().Apply(env, UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel1},
		DestChainSelector:  sel2,
		AllowlistEnabled:   true,
		AddedSenders:       []string{"0x000000000000000000000000000000000000aBcD"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, stub.allowlistCalls)
}

func TestUpdateSenderAllowlist_Apply_AdapterError(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerEVMOnchain(&stubOnchainAdapter{onchainOpErr: errors.New("boom")})
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
		Logger:      logger.Test(t),
	}
	_, err := UpdateSenderAllowlist().Apply(env, UpdateSenderAllowlistInput{
		CommitteeQualifier: "committee-a",
		ChainSelectors:     []uint64{sel1},
		DestChainSelector:  sel2,
	})
	require.ErrorContains(t, err, "ApplyAllowlistUpdates failed")
}
