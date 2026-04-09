package common

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	// Pool type identifiers used across all chain families. These are logical
	// identifiers stored in the datastore; each chain's adapter maps them to
	// the concrete contract implementation.
	BurnMintTokenPoolType    = "BurnMintTokenPool"
	LockReleaseTokenPoolType = "LockReleaseTokenPool"
)

// PoolCapability describes a token pool type and version a chain can deploy.
type PoolCapability struct {
	PoolType    string
	PoolVersion *semver.Version
}

// TokenCombination represents a local/remote pool pairing. "Local" is the pool
// on the chain being configured; "remote" is the counterpart on the other chain.
// Because every chain deploys both pools, a transfer can flow in either direction.
type TokenCombination struct {
	localPoolType           string
	localPoolVersion        string
	localPoolQualifier      string
	localPoolCCVQualifiers  []string
	remotePoolType          string
	remotePoolVersion       string
	remotePoolQualifier     string
	remotePoolCCVQualifiers []string
	expectedReceiptIssuers  int
	expectedVerifierResults int
}

// LocalPoolAddressRef returns the address ref for the local token pool.
func (s TokenCombination) LocalPoolAddressRef() datastore.AddressRef {
	qualifier := s.localPoolQualifier
	if qualifier == "" {
		qualifier = fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.localPoolType, s.localPoolVersion, s.localPoolCCVQualifiers, s.remotePoolType, s.remotePoolVersion, s.remotePoolCCVQualifiers)
	}
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.localPoolType),
		Version:   semver.MustParse(s.localPoolVersion),
		Qualifier: qualifier,
	}
}

// RemotePoolAddressRef returns the address ref for the remote (counterpart) token pool.
func (s TokenCombination) RemotePoolAddressRef() datastore.AddressRef {
	qualifier := s.remotePoolQualifier
	if qualifier == "" {
		qualifier = fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.remotePoolType, s.remotePoolVersion, s.remotePoolCCVQualifiers, s.localPoolType, s.localPoolVersion, s.localPoolCCVQualifiers)
	}
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.remotePoolType),
		Version:   semver.MustParse(s.remotePoolVersion),
		Qualifier: qualifier,
	}
}

// LocalPoolCCVQualifiers returns the CCV qualifiers for the local token pool.
func (s TokenCombination) LocalPoolCCVQualifiers() []string {
	return s.localPoolCCVQualifiers
}

// RemotePoolCCVQualifiers returns the CCV qualifiers for the remote token pool.
func (s TokenCombination) RemotePoolCCVQualifiers() []string {
	return s.remotePoolCCVQualifiers
}

// ExpectedReceiptIssuers returns the expected number of receipt issuers for the token combination.
func (s TokenCombination) ExpectedReceiptIssuers() int {
	return s.expectedReceiptIssuers
}

// ExpectedVerifierResults returns the expected number of verifier results for the token combination.
func (s TokenCombination) ExpectedVerifierResults() int {
	return s.expectedVerifierResults
}

func (s TokenCombination) FinalityConfig() protocol.Finality {
	if semver.MustParse(s.localPoolVersion).GreaterThanEqual(semver.MustParse("2.0.0")) {
		return 1 // We can use fast-finality if local pool is 2.0.0 or higher
	}
	return 0 // Otherwise use default finality
}

// AllTokenCombinations returns all possible token combinations.
func AllTokenCombinations() []TokenCombination {
	return []TokenCombination{
		{ // 1.6.1 burn <-> 1.6.1 burn
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "1.6.1",
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "1.6.1",
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.6.1 burn <-> 2.0.0 burn
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "1.6.1",
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn <-> 1.6.1 burn
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{DefaultCommitteeVerifierQualifier},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "1.6.1",
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 lock <-> 2.0.0 burn
			localPoolType:           LockReleaseTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{DefaultCommitteeVerifierQualifier},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn <-> 2.0.0 release
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{DefaultCommitteeVerifierQualifier},
			remotePoolType:          LockReleaseTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn <-> 2.0.0 burn
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{DefaultCommitteeVerifierQualifier},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn <-> 2.0.0 burn (Default and Secondary CCV)
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5, // default CCV, secondary CCV, token pool, executor, network fee
			expectedVerifierResults: 2, // default CCV, secondary CCV
		},
		{ // 2.0.0 burn <-> 2.0.0 burn (No CCV)
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{},
			expectedReceiptIssuers:  4, // default CCV, token pool, executor, network fee
			expectedVerifierResults: 1, // default CCV
		},
		{ // 2.0.0 burn <-> 2.0.0 burn (Secondary CCV)
			localPoolType:           BurnMintTokenPoolType,
			localPoolVersion:        "2.0.0",
			localPoolCCVQualifiers:  []string{SecondaryCommitteeVerifierQualifier},
			remotePoolType:          BurnMintTokenPoolType,
			remotePoolVersion:       "2.0.0",
			remotePoolCCVQualifiers: []string{SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  5, // secondary CCV, default CCV, token pool, executor, network fee
			expectedVerifierResults: 2, // secondary CCV, default CCV (defaultCCV included because ccipReceiveGasLimit > 0)
		},
	}
}

// Is17Combination returns true when both local and remote pools are v2.0.0.
func Is17Combination(tc TokenCombination) bool {
	return semver.MustParse(tc.localPoolVersion).Equal(semver.MustParse("2.0.0")) &&
		semver.MustParse(tc.remotePoolVersion).Equal(semver.MustParse("2.0.0"))
}

func All17TokenCombinations() []TokenCombination {
	combinations := []TokenCombination{}
	for _, tc := range AllTokenCombinations() {
		if Is17Combination(tc) {
			combinations = append(combinations, tc)
		}
	}
	return combinations
}

// ComputeTokenCombinations derives valid token pool pairings from per-chain capabilities.
// It generates combinations for every compatible (local, remote) pair where at least two
// chains support the required types. CCV qualifiers are assigned based on pool version
// (2.0.0 pools use the available committee qualifiers from the topology).
//
// Pairing rules:
//   - BurnMint pairs with BurnMint (any version combination)
//   - LockRelease pairs with BurnMint (in both directions)
func ComputeTokenCombinations(
	capabilities map[uint64][]PoolCapability,
	topology *offchain.EnvironmentTopology,
) []TokenCombination {
	// Collect the set of distinct pool capabilities across all chains.
	type capKey struct {
		poolType string
		version  string
	}
	capSet := make(map[capKey]bool)
	for _, caps := range capabilities {
		for _, c := range caps {
			capSet[capKey{c.PoolType, c.PoolVersion.String()}] = true
		}
	}

	// Convert to a sorted slice for deterministic output.
	allCaps := make([]capKey, 0, len(capSet))
	for k := range capSet {
		allCaps = append(allCaps, k)
	}
	sort.Slice(allCaps, func(i, j int) bool {
		if allCaps[i].poolType != allCaps[j].poolType {
			return allCaps[i].poolType < allCaps[j].poolType
		}
		return allCaps[i].version < allCaps[j].version
	})

	isCompatible := func(localType, remoteType string) bool {
		if localType == BurnMintTokenPoolType && remoteType == BurnMintTokenPoolType {
			return true
		}
		if localType == LockReleaseTokenPoolType && remoteType == BurnMintTokenPoolType {
			return true
		}
		if localType == BurnMintTokenPoolType && remoteType == LockReleaseTokenPoolType {
			return true
		}
		return false
	}

	// Determine CCV qualifier permutations available from the topology.
	ccvQualifierSets := ccvQualifierPermutations(topology)

	var combos []TokenCombination
	for _, local := range allCaps {
		for _, remote := range allCaps {
			if !isCompatible(local.poolType, remote.poolType) {
				continue
			}
			// At least two chains must support the required types.
			localCount, remoteCount := 0, 0
			for _, caps := range capabilities {
				hasLocal, hasRemote := false, false
				for _, c := range caps {
					if c.PoolType == local.poolType && c.PoolVersion.String() == local.version {
						hasLocal = true
					}
					if c.PoolType == remote.poolType && c.PoolVersion.String() == remote.version {
						hasRemote = true
					}
				}
				if hasLocal {
					localCount++
				}
				if hasRemote {
					remoteCount++
				}
			}
			if localCount == 0 || remoteCount == 0 || (localCount+remoteCount) < 2 {
				continue
			}

			localV := semver.MustParse(local.version)
			remoteV := semver.MustParse(remote.version)
			v200 := semver.MustParse("2.0.0")
			localNeedsCCV := localV.GreaterThanEqual(v200)
			remoteNeedsCCV := remoteV.GreaterThanEqual(v200)

			if !localNeedsCCV && !remoteNeedsCCV {
				combos = append(combos, newTokenCombination(local.poolType, local.version, nil, remote.poolType, remote.version, nil))
			} else {
				for _, qs := range ccvQualifierSets {
					var localQ, remoteQ []string
					if localNeedsCCV {
						localQ = qs
					}
					if remoteNeedsCCV {
						remoteQ = qs
					}
					combos = append(combos, newTokenCombination(local.poolType, local.version, localQ, remote.poolType, remote.version, remoteQ))
				}
			}
		}
	}
	return combos
}

func newTokenCombination(localType, localVersion string, localCCVs []string, remoteType, remoteVersion string, remoteCCVs []string) TokenCombination {
	baseCCVCount := 1 // default CCV always present
	extraIssuers := 3 // token pool, executor, network fee

	localCCVCount := len(localCCVs)
	if localCCVCount == 0 {
		localCCVCount = baseCCVCount
	}

	return TokenCombination{
		localPoolType:           localType,
		localPoolVersion:        localVersion,
		localPoolCCVQualifiers:  localCCVs,
		remotePoolType:          remoteType,
		remotePoolVersion:       remoteVersion,
		remotePoolCCVQualifiers: remoteCCVs,
		expectedReceiptIssuers:  localCCVCount + extraIssuers,
		expectedVerifierResults: localCCVCount,
	}
}

// ccvQualifierPermutations returns the set of CCV qualifier slices to exercise,
// derived from the topology's available committees. It always includes the
// empty-qualifier case (no explicit CCVs) for pools that support it.
func ccvQualifierPermutations(topology *offchain.EnvironmentTopology) [][]string {
	result := [][]string{
		{}, // no explicit CCVs
	}
	if topology == nil || topology.NOPTopology == nil {
		return result
	}

	qualifiers := make([]string, 0, len(topology.NOPTopology.Committees))
	for q := range topology.NOPTopology.Committees {
		qualifiers = append(qualifiers, q)
	}
	sort.Strings(qualifiers)

	// Single-qualifier sets.
	for _, q := range qualifiers {
		result = append(result, []string{q})
	}
	// If there are at least two committees, also add the "all qualifiers" set.
	if len(qualifiers) >= 2 {
		result = append(result, qualifiers)
	}

	return result
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
// all exist as committees in the topology, and when ds is non-nil, whose local and
// remote pool address refs exist in ds for every selector (each chain deploys both
// pools across bidirectional transfer configs).
// Pass ds nil to skip the datastore check.
func FilterTokenCombinations(combos []TokenCombination, topology *offchain.EnvironmentTopology, ds datastore.DataStore, selectors []uint64) []TokenCombination {
	filtered := make([]TokenCombination, 0, len(combos))
	for _, combo := range combos {
		if !qualifiersAvailable(combo.LocalPoolCCVQualifiers(), topology) ||
			!qualifiersAvailable(combo.RemotePoolCCVQualifiers(), topology) {
			continue
		}
		if ds != nil && len(selectors) > 0 && !tokenCombinationPoolsExistInDataStore(ds, selectors, combo) {
			continue
		}
		filtered = append(filtered, combo)
	}
	return filtered
}

func tokenCombinationPoolsExistInDataStore(ds datastore.DataStore, selectors []uint64, combo TokenCombination) bool {
	local := combo.LocalPoolAddressRef()
	remote := combo.RemotePoolAddressRef()
	for _, sel := range selectors {
		if !dataStoreHasAddressRef(ds, sel, local) || !dataStoreHasAddressRef(ds, sel, remote) {
			return false
		}
	}
	return true
}

func dataStoreHasAddressRef(ds datastore.DataStore, chainSelector uint64, ref datastore.AddressRef) bool {
	_, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		chainSelector,
		ref.Type,
		ref.Version,
		ref.Qualifier,
	))
	return err == nil
}
