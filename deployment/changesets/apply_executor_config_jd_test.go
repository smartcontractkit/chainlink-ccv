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

type jdMockExecutorAdapter struct {
	requiresJD bool
}

var _ ccvadapters.ExecutorConfigAdapter = (*jdMockExecutorAdapter)(nil)

func (m *jdMockExecutorAdapter) GetDeployedChains(_ datastore.DataStore, _ string) []uint64 {
	return nil
}

func (m *jdMockExecutorAdapter) RequiresNodeChainSupportInJD() bool {
	return m.requiresJD
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

func TestFilterChainsRequiringJDSupport_FiltersPerAdapter(t *testing.T) {
	evmSel := chainsel.TEST_90000001.Selector
	aptosSel := chainsel.TEST_90000002.Selector

	ccvadapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &jdMockExecutorAdapter{requiresJD: true})
	ccvadapters.GetExecutorRegistry().Register(chainsel.FamilyAptos, &jdMockExecutorAdapter{requiresJD: false})

	filtered, err := filterChainsRequiringJDSupport([]uint64{evmSel, aptosSel})
	require.NoError(t, err)
	assert.Equal(t, []uint64{evmSel}, filtered)
}

func TestValidateExecutorChainSupport_SkipsJDWhenOffchainNil(t *testing.T) {
	evmSel := chainsel.TEST_90000001.Selector
	aptosSel := chainsel.TEST_90000002.Selector

	pool := ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			evmSel: {
				NOPAliases:        []shared.NOPAlias{"nop1"},
				ExecutionInterval: 5 * time.Second,
			},
			aptosSel: {
				NOPAliases:        []shared.NOPAlias{"nop1"},
				ExecutionInterval: 5 * time.Second,
			},
		},
	}

	err := validateExecutorChainSupport(deployment.Environment{}, pool, []shared.NOPAlias{"nop1"})
	require.NoError(t, err)
}
