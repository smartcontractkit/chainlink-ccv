package migration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
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
