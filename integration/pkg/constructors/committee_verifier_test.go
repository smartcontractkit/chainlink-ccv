package constructors

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

// stubChain implements only the slice of legacyevm.Chain that NewVerificationCoordinator uses
// (Client and HeadTracker). The embedded nil interface covers the rest: any call beyond those
// two panics, which is exactly the desired outcome if the constructor starts reaching further.
type stubChain struct {
	legacyevm.Chain
	chainClient client.Client
}

func (c stubChain) Client() client.Client      { return c.chainClient }
func (c stubChain) HeadTracker() heads.Tracker { return heads.NullTracker }

// stubDataSource satisfies sqlutil.DataSource with no database. NewVerificationCoordinator only
// requires a non-nil DataSource at construction — every consumer hands it to stores that defer
// all queries until Start — so an embedded nil interface suffices, and any actual use panics.
type stubDataSource struct {
	sqlutil.DataSource
}

// fakeSigner implements verifier.MessageSigner without a keystore.
type fakeSigner struct{}

func (fakeSigner) Sign([]byte) ([]byte, error) { return nil, nil }

// newTestConfig builds a valid commit.Config covering the given selectors, using the legacy
// single-aggregator wiring (aggregator_address, no secret_name), which maps its credential to
// the empty SecretName key.
func newTestConfig(selectors ...protocol.ChainSelector) commit.Config {
	onRamps := make(map[string]string, len(selectors))
	verifiers := make(map[string]string, len(selectors))
	for _, sel := range selectors {
		key := strconv.FormatUint(uint64(sel), 10)
		onRamps[key] = "0x0000000000000000000000000000000000000001"
		verifiers[key] = "0x0000000000000000000000000000000000000002"
	}
	return commit.Config{
		VerifierID:                 "test-verifier",
		AggregatorAddress:          "localhost:50051",
		SignerAddress:              commit.AutoSignerAddress,
		CommitteeVerifierAddresses: verifiers,
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses: onRamps,
		},
	}
}

func testAggregatorSecrets() map[string]*hmac.ClientConfig {
	return map[string]*hmac.ClientConfig{
		"": {APIKey: "api-key", Secret: "secret"},
	}
}

// TestNewVerificationCoordinator_SkipsFailedChains guards the incident regression where a single
// chain whose source reader could not be built (e.g. an unreachable RPC) aborted construction and
// prevented every other valid chain from starting.
func TestNewVerificationCoordinator_SkipsFailedChains(t *testing.T) {
	const (
		goodSelector = protocol.ChainSelector(5009297550715157269)
		badSelector  = protocol.ChainSelector(14767482510783485446)
	)

	// The bad chain's chain client is nil, so NewEVMSourceReader fails its validation and the
	// coordinator must skip the chain rather than fail the whole constructor. The good chain's
	// client is an unregistered testify mock, so any unexpected RPC at construction fails loudly.
	relayers := map[protocol.ChainSelector]legacyevm.Chain{
		goodSelector: stubChain{chainClient: clienttest.NewClient(t)},
		badSelector:  stubChain{},
	}

	coordinator, err := NewVerificationCoordinator(
		logger.Test(t),
		newTestConfig(goodSelector, badSelector),
		testAggregatorSecrets(),
		protocol.UnknownAddress{}, // unchecked: the config opts out via AutoSignerAddress
		fakeSigner{},
		relayers,
		&stubDataSource{},
	)
	require.NoError(t, err, "one failed chain must not abort the remaining chains")
	require.NotNil(t, coordinator)
}

// TestNewVerificationCoordinator_NoUsableChains checks the guard rail added alongside skip-and-
// log: when no chain produces a working source reader, the constructor must fail loudly instead
// of silently starting a coordinator that verifies nothing.
func TestNewVerificationCoordinator_NoUsableChains(t *testing.T) {
	selector := protocol.ChainSelector(5009297550715157269)

	relayers := map[protocol.ChainSelector]legacyevm.Chain{
		selector: stubChain{}, // nil client: no chain can build a source reader
	}

	_, err := NewVerificationCoordinator(
		logger.Test(t),
		newTestConfig(selector),
		testAggregatorSecrets(),
		protocol.UnknownAddress{},
		fakeSigner{},
		relayers,
		&stubDataSource{},
	)
	require.ErrorContains(t, err, "no source readers configured")
}
