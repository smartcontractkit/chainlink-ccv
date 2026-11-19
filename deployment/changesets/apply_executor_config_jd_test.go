package changesets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_node_chain_support"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

type jdMockExecutorAdapter struct{}

var _ ccvadapters.ExecutorConfigAdapter = (*jdMockExecutorAdapter)(nil)

func (m *jdMockExecutorAdapter) GetDeployedChains(_ datastore.DataStore, _ string) []uint64 {
	return nil
}

func (m *jdMockExecutorAdapter) ResolveExecutorAddress(_ datastore.DataStore, _ uint64, _ string) (string, error) {
	return "0xexec", nil
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

	err := validateExecutorChainSupport(deployment.Environment{}, pool, []shared.NOPAlias{"nop1"}, nil)
	require.NoError(t, err)
}

func TestFetchNodeChainSupportDoesNotReuseStoredReport(t *testing.T) {
	selector := chainsel.SOLANA_DEVNET.Selector
	chainID, err := chainsel.GetChainIDFromSelector(selector)
	require.NoError(t, err)
	shared.RegisterChainTypeFamily(nodev1.ChainType_CHAIN_TYPE_SOLANA, chainsel.FamilySolana)

	client := &stubOffchainClient{
		nodes: map[string]string{"node-1": "nop1"},
		chainConfigs: []*nodev1.ChainConfig{{
			NodeId: "node-1",
			Chain:  &nodev1.Chain{Id: chainID, Type: nodev1.ChainType_CHAIN_TYPE_SOLANA},
		}},
	}
	input := fetch_node_chain_support.FetchNodeChainSupportInput{NOPAliases: []string{"nop1"}}
	staleReport := operations.NewReport(
		fetch_node_chain_support.FetchNodeChainSupport.Def(),
		input,
		fetch_node_chain_support.FetchNodeChainSupportOutput{SupportedChains: make(shared.ChainSupportByNOP)},
		nil,
	)
	lggr := logger.Test(t)
	env := deployment.Environment{
		Logger:   lggr,
		Offchain: client,
		NodeIDs:  []string{"node-1"},
		OperationsBundle: operations.NewBundle(t.Context, lggr, operations.NewMemoryReporter(
			operations.WithReports([]operations.Report[any, any]{staleReport.ToGenericReport()}),
		)),
	}

	supportedChains, err := fetchNodeChainSupport(env, input.NOPAliases, nil)
	require.NoError(t, err)
	require.Equal(t, []uint64{selector}, supportedChains["nop1"])
}
