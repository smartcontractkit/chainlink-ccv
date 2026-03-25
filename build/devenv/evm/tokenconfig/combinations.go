package tokenconfig

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v2_0_0/operations/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v2_0_0/operations/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// TokenCombination represents a source and destination pool combination.
type TokenCombination struct {
	sourcePoolType          string
	sourcePoolVersion       string
	sourcePoolQualifier     string
	sourcePoolCCVQualifiers []string
	destPoolType            string
	destPoolVersion         string
	destPoolQualifier       string
	destPoolCCVQualifiers   []string
	expectedReceiptIssuers  int
	expectedVerifierResults int
}

// SourcePoolAddressRef returns the address ref for the source token pool that can be used to query the datastore.
func (s TokenCombination) SourcePoolAddressRef() datastore.AddressRef {
	qualifier := s.sourcePoolQualifier
	if qualifier == "" {
		qualifier = fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.sourcePoolType, s.sourcePoolVersion, s.sourcePoolCCVQualifiers, s.destPoolType, s.destPoolVersion, s.destPoolCCVQualifiers)
	}
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.sourcePoolType),
		Version:   semver.MustParse(s.sourcePoolVersion),
		Qualifier: qualifier,
	}
}

// DestPoolAddressRef returns the address ref for the destination token pool that can be used to query the datastore.
func (s TokenCombination) DestPoolAddressRef() datastore.AddressRef {
	qualifier := s.destPoolQualifier
	if qualifier == "" {
		qualifier = fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.destPoolType, s.destPoolVersion, s.destPoolCCVQualifiers, s.sourcePoolType, s.sourcePoolVersion, s.sourcePoolCCVQualifiers)
	}
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.destPoolType),
		Version:   semver.MustParse(s.destPoolVersion),
		Qualifier: qualifier,
	}
}

func (s TokenCombination) SourcePoolCCVQualifiers() []string {
	return s.sourcePoolCCVQualifiers
}

func (s TokenCombination) DestPoolCCVQualifiers() []string {
	return s.destPoolCCVQualifiers
}

func (s TokenCombination) ExpectedReceiptIssuers() int {
	return s.expectedReceiptIssuers
}

func (s TokenCombination) ExpectedVerifierResults() int {
	return s.expectedVerifierResults
}

func (s TokenCombination) FinalityConfig() uint16 {
	if semver.MustParse(s.sourcePoolVersion).GreaterThanEqual(semver.MustParse("2.0.0")) {
		return 1 // We can use fast-finality if source pool is 2.0.0 or higher
	}
	return 0 // Otherwise use default finality
}

// AllTokenCombinations returns all possible EVM token combinations.
func AllTokenCombinations() []TokenCombination {
	return []TokenCombination{
		{ // 1.6.1 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 1.6.1 burn -> 2.0.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 lock -> 2.0.0 burn
			sourcePoolType:          string(lock_release_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 burn -> 2.0.0 release
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.DefaultCommitteeVerifierQualifier},
			destPoolType:            string(lock_release_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 burn -> 2.0.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 burn -> 2.0.0 mint (Default and Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.DefaultCommitteeVerifierQualifier, common.SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.DefaultCommitteeVerifierQualifier, common.SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5,
			expectedVerifierResults: 2,
		},
		{ // 2.0.0 burn -> 2.0.0 mint (No CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{},
			expectedReceiptIssuers:  4,
			expectedVerifierResults: 1,
		},
		{ // 2.0.0 burn -> 2.0.0 mint (Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{common.SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{common.SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5,
			expectedVerifierResults: 2,
		},
	}
}

func All17TokenCombinations() []TokenCombination {
	var combinations []TokenCombination
	for _, tc := range AllTokenCombinations() {
		if semver.MustParse(tc.sourcePoolVersion).Equal(semver.MustParse("2.0.0")) && semver.MustParse(tc.destPoolVersion).Equal(semver.MustParse("2.0.0")) {
			combinations = append(combinations, tc)
		}
	}
	return combinations
}

// qualifiersAvailable returns true if all qualifiers exist as committees in the topology.
func qualifiersAvailable(qualifiers []string, topology *offchain.EnvironmentTopology) bool {
	if topology == nil || topology.NOPTopology == nil {
		return len(qualifiers) == 0
	}
	for _, q := range qualifiers {
		if _, ok := topology.NOPTopology.Committees[q]; !ok {
			return false
		}
	}
	return true
}

// FilterTokenCombinations returns only the token combinations whose CCV qualifiers
// all exist as committees in the topology.
func FilterTokenCombinations(combos []TokenCombination, topology *offchain.EnvironmentTopology) []TokenCombination {
	filtered := make([]TokenCombination, 0, len(combos))
	for _, combo := range combos {
		if qualifiersAvailable(combo.SourcePoolCCVQualifiers(), topology) &&
			qualifiersAvailable(combo.DestPoolCCVQualifiers(), topology) {
			filtered = append(filtered, combo)
		}
	}
	return filtered
}
