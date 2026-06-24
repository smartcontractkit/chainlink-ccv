package changesets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

type jdMockExecutorAdapter struct{}

var _ ccvadapters.ExecutorConfigAdapter = (*jdMockExecutorAdapter)(nil)

func (m *jdMockExecutorAdapter) GetDeployedChains(_ datastore.DataStore, _ string) []uint64 {
	return nil
}

func (m *jdMockExecutorAdapter) BuildChainConfig(_ datastore.DataStore, _ uint64, _ string) (executor.ChainConfiguration, error) {
	return executor.ChainConfiguration{
		DestinationChainConfig: chainaccess.DestinationChainConfig{
			OffRampAddress: "0xoff",
			RmnAddress:     "0xrmn",
		},
		DefaultExecutorAddress: "0xexec",
	}, nil
}

type jdMockExecutorAdapterSkipJD struct {
	jdMockExecutorAdapter
}

var _ ccvadapters.ExecutorNodeChainJDSupport = (*jdMockExecutorAdapterSkipJD)(nil)

func (m *jdMockExecutorAdapterSkipJD) RequiresNodeChainSupportInJD() bool {
	return false
}

func TestFilterChainsRequiringJDSupport_FiltersPerAdapter(t *testing.T) {
	evmSel := chainsel.TEST_90000001.Selector
	// TEST_90000002 is also EVM; use a different family to exercise per-adapter filtering.
	nonJDSel := chainsel.SOLANA_DEVNET.Selector

	ccvadapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &jdMockExecutorAdapter{})
	ccvadapters.GetExecutorRegistry().Register(chainsel.FamilySolana, &jdMockExecutorAdapterSkipJD{})

	filtered, err := filterChainsRequiringJDSupport([]uint64{evmSel, nonJDSel})
	require.NoError(t, err)
	assert.Equal(t, []uint64{evmSel}, filtered)
}

func TestValidateExecutorChainSupport_SkipsJDWhenOffchainNil(t *testing.T) {
	evmSel := chainsel.TEST_90000001.Selector
	nonJDSel := chainsel.SOLANA_DEVNET.Selector

	pool := ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			evmSel: {
				NOPAliases:        []shared.NOPAlias{"nop1"},
				ExecutionInterval: 5 * time.Second,
			},
			nonJDSel: {
				NOPAliases:        []shared.NOPAlias{"nop1"},
				ExecutionInterval: 5 * time.Second,
			},
		},
	}

	err := validateExecutorChainSupport(deployment.Environment{}, pool, []shared.NOPAlias{"nop1"})
	require.NoError(t, err)
}
