package migration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

// aggregatorWithClients builds a running aggregator whose credential map has been dropped, which is
// what loading a devenv output file produces: AggregatorOutput.ClientCredentials is toml:"-" while
// api_clients.api_key_pairs round-trips.
func aggregatorWithClients(clients ...*services.AggregatorClientConfig) *services.AggregatorInput {
	return &services.AggregatorInput{
		CommitteeName: "default",
		APIClients:    clients,
		Out:           &services.AggregatorOutput{Address: "default-aggregator:50051"},
	}
}

func TestHydrateAggregatorCredentialsRecoversKeysFromClientConfig(t *testing.T) {
	t.Parallel()
	agg := aggregatorWithClients(
		&services.AggregatorClientConfig{
			ClientID:    "default-verifier-1",
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: "key-1", Secret: "secret-1"}},
		},
		&services.AggregatorClientConfig{
			ClientID:    "indexer",
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: "key-2", Secret: "secret-2"}},
		},
	)

	hydrateAggregatorCredentials([]*services.AggregatorInput{agg})

	got, ok := agg.Out.GetCredentialsForClient("default-verifier-1")
	require.True(t, ok, "the verifier's credentials must be recoverable from the client config")
	assert.Equal(t, hmacutil.Credentials{APIKey: "key-1", Secret: "secret-1"}, got,
		"the recovered credentials must be the ones the running aggregator was started with")
}

// Regenerating would hand the verifier a credential the running aggregator has never seen, which
// fails at authentication time rather than here.
func TestHydrateAggregatorCredentialsDoesNotInventKeys(t *testing.T) {
	t.Parallel()
	agg := aggregatorWithClients(&services.AggregatorClientConfig{
		ClientID:    "default-verifier-1",
		APIKeyPairs: []*services.AggregatorAPIKeyPair{{}},
	})

	hydrateAggregatorCredentials([]*services.AggregatorInput{agg})

	_, ok := agg.Out.GetCredentialsForClient("default-verifier-1")
	assert.False(t, ok, "an empty key pair must not be filled in with a freshly generated one")
}

func TestHydrateAggregatorCredentialsKeepsExistingMap(t *testing.T) {
	t.Parallel()
	agg := aggregatorWithClients(&services.AggregatorClientConfig{
		ClientID:    "default-verifier-1",
		APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: "from-config", Secret: "from-config"}},
	})
	agg.Out.ClientCredentials = map[string]hmacutil.Credentials{
		"default-verifier-1": {APIKey: "live", Secret: "live"},
	}

	hydrateAggregatorCredentials([]*services.AggregatorInput{agg})

	got, ok := agg.Out.GetCredentialsForClient("default-verifier-1")
	require.True(t, ok)
	assert.Equal(t, "live", got.APIKey, "an aggregator launched in this process keeps its live credentials")
}

// topologyWithPools builds a topology whose executor pools place the given NOP on the given chains.
func topologyWithPools(pools map[string]map[string][]string) *ccvdeployment.EnvironmentTopology {
	out := &ccvdeployment.EnvironmentTopology{ExecutorPools: map[string]ccvdeployment.ExecutorPoolConfig{}}
	for pool, chains := range pools {
		cfg := ccvdeployment.ExecutorPoolConfig{ChainConfigs: map[string]ccvdeployment.ChainExecutorPoolConfig{}}
		for chain, aliases := range chains {
			cfg.ChainConfigs[chain] = ccvdeployment.ChainExecutorPoolConfig{NOPAliases: aliases}
		}
		out.ExecutorPools[pool] = cfg
	}
	return out
}

// Prod runs a single executor pool with one identity per operator, so this is the shape every
// migration takes today.
func TestRequireDisjointExecutorChainsAllowsOneExecutorPerNOP(t *testing.T) {
	t.Parallel()
	executors := []*executorsvc.Input{
		{ContainerName: "default-executor-1", NOPAlias: "node-0", ExecutorQualifier: "default"},
		{ContainerName: "default-executor-2", NOPAlias: "node-1", ExecutorQualifier: "default"},
	}
	topology := topologyWithPools(map[string]map[string][]string{
		"default": {"chainA": {"node-0", "node-1"}, "chainB": {"node-0", "node-1"}},
	})

	require.NoError(t, requireDisjointExecutorChains(executors,
		map[string]struct{}{"node-0": {}, "node-1": {}}, topology))
}

// Disjoint chains are safe with a shared account: the same address has independent nonces per chain.
func TestRequireDisjointExecutorChainsAllowsSeveralExecutorsOnDifferentChains(t *testing.T) {
	t.Parallel()
	executors := []*executorsvc.Input{
		{ContainerName: "exec-a", NOPAlias: "node-0", ExecutorQualifier: "default"},
		{ContainerName: "exec-b", NOPAlias: "node-0", ExecutorQualifier: "custom"},
	}
	topology := topologyWithPools(map[string]map[string][]string{
		"default": {"chainA": {"node-0"}},
		"custom":  {"chainB": {"node-0"}},
	})

	require.NoError(t, requireDisjointExecutorChains(executors, map[string]struct{}{"node-0": {}}, topology))
}

// Two executors importing one account and both running chainA would race each other's nonces. This
// is the shape env-cl.toml describes, where node-0's two pools cover the same chains.
func TestRequireDisjointExecutorChainsRejectsSharedAccountOnSharedChain(t *testing.T) {
	t.Parallel()
	executors := []*executorsvc.Input{
		{ContainerName: "default-executor-1", NOPAlias: "node-0", ExecutorQualifier: "default"},
		{ContainerName: "custom-executor-1", NOPAlias: "node-0", ExecutorQualifier: "custom"},
	}
	topology := topologyWithPools(map[string]map[string][]string{
		"default": {"chainA": {"node-0"}},
		"custom":  {"chainA": {"node-0"}},
	})

	err := requireDisjointExecutorChains(executors, map[string]struct{}{"node-0": {}}, topology)
	require.ErrorContains(t, err, "chainA")
	require.ErrorContains(t, err, "node-0")
	require.ErrorContains(t, err, "nonces")
}

// An operator staying in CL mode keeps whatever executor layout it has; only migrating NOPs are
// constrained by what the cutover can import.
func TestRequireDisjointExecutorChainsIgnoresNonMigratingNOPs(t *testing.T) {
	t.Parallel()
	executors := []*executorsvc.Input{
		{ContainerName: "a", NOPAlias: "staying", ExecutorQualifier: "default"},
		{ContainerName: "b", NOPAlias: "staying", ExecutorQualifier: "custom"},
	}
	topology := topologyWithPools(map[string]map[string][]string{
		"default": {"chainA": {"staying"}},
		"custom":  {"chainA": {"staying"}},
	})

	require.NoError(t, requireDisjointExecutorChains(executors, map[string]struct{}{"node-0": {}}, topology))
}

// An executor with no qualifier belongs to the default pool, which is what ApplyDefaults gives it.
func TestExecutorChainsDefaultsTheQualifier(t *testing.T) {
	t.Parallel()
	topology := topologyWithPools(map[string]map[string][]string{
		"default": {"chainA": {"node-0"}, "chainB": {"other"}},
	})

	got := executorChains(&executorsvc.Input{NOPAlias: "node-0"}, topology)

	require.Len(t, got, 1)
	require.Contains(t, got, "chainA")
}

// An aggregator that was never launched has no Out to attach credentials to. Creating one would put
// an aggregator with no address into the committee's list, so it is left as it is.
func TestHydrateAggregatorCredentialsSkipsUnlaunchedAggregators(t *testing.T) {
	t.Parallel()
	agg := &services.AggregatorInput{
		CommitteeName: "default",
		APIClients: []*services.AggregatorClientConfig{{
			ClientID:    "default-verifier-1",
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: "key-1", Secret: "secret-1"}},
		}},
	}

	hydrateAggregatorCredentials([]*services.AggregatorInput{nil, agg})

	assert.Nil(t, agg.Out, "an aggregator with no output must not be given one")
}
