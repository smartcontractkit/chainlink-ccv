package common

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/latest/operations/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/latest/operations/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
)

const (
	// These qualifiers are used to distinguish between multiple deployments of the committee verifier proxy and mock receiver
	// on the same chain.
	// In the smoke test deployments these are the qualifiers that are used by default.
	DefaultCommitteeVerifierQualifier = "default"
	DefaultReceiverQualifier          = "default"
	DefaultExecutorQualifier          = "default"

	SecondaryCommitteeVerifierQualifier = "secondary"
	SecondaryReceiverQualifier          = "secondary"

	TertiaryCommitteeVerifierQualifier = "tertiary"
	TertiaryReceiverQualifier          = "tertiary"

	QuaternaryReceiverQualifier = "quaternary"

	CustomExecutorQualifier = "custom"

	CCTPPrimaryReceiverQualifier   = "cctp-primary"
	CCTPSecondaryReceiverQualifier = "cctp-secondary"

	LombardContractsQualifier       = "Lombard"
	LombardPrimaryReceiverQualifier = "lombard-primary"
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

// SourcePoolCCVQualifiers returns the CCV qualifiers for the source token pool.
func (s TokenCombination) SourcePoolCCVQualifiers() []string {
	return s.sourcePoolCCVQualifiers
}

// DestPoolCCVQualifiers returns the CCV qualifiers for the destination token pool.
func (s TokenCombination) DestPoolCCVQualifiers() []string {
	return s.destPoolCCVQualifiers
}

// ExpectedReceiptIssuers returns the expected number of receipt issuers for the token combination.
func (s TokenCombination) ExpectedReceiptIssuers() int {
	return s.expectedReceiptIssuers
}

// ExpectedVerifierResults returns the expected number of verifier results for the token combination.
func (s TokenCombination) ExpectedVerifierResults() int {
	return s.expectedVerifierResults
}

func (s TokenCombination) FinalityConfig() uint16 {
	if semver.MustParse(s.sourcePoolVersion).GreaterThanEqual(semver.MustParse("2.0.0")) {
		return 1 // We can use fast-finality if source pool is 2.0.0 or higher
	}
	return 0 // Otherwise use default finality
}

// AllTokenCombinations returns all possible token combinations.
func AllTokenCombinations() []TokenCombination {
	return []TokenCombination{
		{ // 1.6.1 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.6.1 burn -> 2.0.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 lock -> 2.0.0 burn
			sourcePoolType:          string(lock_release_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn -> 2.0.0 release
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(lock_release_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn -> 2.0.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn -> 2.0.0 mint (Default and Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5, // default CCV, secondary CCV, token pool, executor, network fee
			expectedVerifierResults: 2, // default CCV, secondary CCV
		},
		{ // 2.0.0 burn -> 2.0.0 mint (No CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn -> 2.0.0 mint (Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "2.0.0",
			sourcePoolCCVQualifiers: []string{SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "2.0.0",
			destPoolCCVQualifiers:   []string{SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5, // secondary CCV, default CCV, token pool, executor, network fee
			expectedVerifierResults: 2, // secondary CCV, default CCV (defaultCCV included because ccipReceiveGasLimit > 0)
		},
	}
}

func All17TokenCombinations() []TokenCombination {
	combinations := []TokenCombination{}
	for _, tc := range AllTokenCombinations() {
		if semver.MustParse(tc.sourcePoolVersion).Equal(semver.MustParse("2.0.0")) && semver.MustParse(tc.destPoolVersion).Equal(semver.MustParse("2.0.0")) {
			combinations = append(combinations, tc)
		}
	}
	return combinations
}

// qualifiersAvailable returns true if all qualifiers exist as committees in the topology.
func qualifiersAvailable(qualifiers []string, topology *deployments.EnvironmentTopology) bool {
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
// all exist as committees in the topology. This ensures that environments with fewer
// committees (e.g. HA topology with only "default") don't attempt to deploy or
// configure token pools referencing non-existent committee verifiers.
func FilterTokenCombinations(combos []TokenCombination, topology *deployments.EnvironmentTopology) []TokenCombination {
	filtered := make([]TokenCombination, 0, len(combos))
	for _, combo := range combos {
		if qualifiersAvailable(combo.SourcePoolCCVQualifiers(), topology) &&
			qualifiersAvailable(combo.DestPoolCCVQualifiers(), topology) {
			filtered = append(filtered, combo)
		}
	}
	return filtered
}
