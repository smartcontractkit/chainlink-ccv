package indexer_config

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// GeneratedVerifier contains the on-chain derived configuration for a verifier.
// Each entry represents one verifier with all its IssuerAddresses across all chains.
type GeneratedVerifier struct {
	Name string
	// IssuerAddresses are all verifier contract addresses for this verifier across all chains
	IssuerAddresses []string
}

// BuildConfigInput contains the input parameters for building the indexer config.
type BuildConfigInput struct {
	// ServiceIdentifier is the identifier for this indexer service (e.g. "default-indexer")
	ServiceIdentifier string
	// VerifierNameToQualifier maps verifier names (matching VerifierConfig.Name) to qualifiers
	// used for looking up addresses in the datastore.
	CommitteeVerifierNameToQualifier map[string]string
	CCTPVerifierNameToQualifier      map[string]string
	// ChainSelectors are the source chains the indexer will monitor.
	// If empty, defaults to all chain selectors available in the environment.
	ChainSelectors []uint64
}

// BuildConfigOutput contains the generated indexer verifier configuration.
type BuildConfigOutput struct {
	// ServiceIdentifier is echoed back for use in storing the config
	ServiceIdentifier string
	// Verifiers contains the on-chain derived config (IssuerAddresses) per verifier name
	Verifiers []GeneratedVerifier
}

// BuildConfigDeps contains the dependencies for building the indexer config.
// Now uses deployment.Environment to access chains for on-chain scanning.
type BuildConfigDeps struct {
	Env deployment.Environment
}

// BuildConfig is an operation that generates the indexer verifier configuration
// by querying the datastore for CommitteeVerifierResolver addresses. It generates one entry
// per verifier name with all IssuerAddresses (resolver addresses) for that verifier across all chains.
var BuildConfig = operations.NewOperation(
	"build-indexer-config",
	semver.MustParse("1.0.0"),
	"Builds the indexer verifier configuration from datastore",
	func(b operations.Bundle, deps BuildConfigDeps, input BuildConfigInput) (BuildConfigOutput, error) {
		ds := deps.Env.DataStore

		verifiers := make([]GeneratedVerifier, 0, len(input.CommitteeVerifierNameToQualifier)+len(input.CCTPVerifierNameToQualifier))

		for name, qualifier := range input.CommitteeVerifierNameToQualifier {
			addresses, err := collectUniqueAddresses(
				ds, input.ChainSelectors, qualifier, committee_verifier.ResolverType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get resolver addresses for verifier %q (qualifier %q): %w", name, qualifier, err)
			}

			verifiers = append(verifiers, GeneratedVerifier{
				Name:            name,
				IssuerAddresses: addresses,
			})
		}

		for name, qualifier := range input.CCTPVerifierNameToQualifier {
			addresses, err := collectUniqueAddresses(
				ds, input.ChainSelectors, qualifier, cctp_verifier.ResolverType)
			if err != nil {
				return BuildConfigOutput{}, fmt.Errorf("failed to get resolver addresses for verifier %q (qualifier %q): %w", name, qualifier, err)
			}
			verifiers = append(verifiers, GeneratedVerifier{
				Name:            name,
				IssuerAddresses: addresses,
			})
		}

		return BuildConfigOutput{
			ServiceIdentifier: input.ServiceIdentifier,
			Verifiers:         verifiers,
		}, nil
	},
)

func collectUniqueAddresses(
	ds datastore.DataStore,
	chainSelectors []uint64,
	qualifier string,
	contractType deployment.ContractType,
) ([]string, error) {
	seen := make(map[string]bool)
	addresses := make([]string, 0)

	for _, chainSelector := range chainSelectors {
		refs := ds.Addresses().Filter(
			datastore.AddressRefByChainSelector(chainSelector),
			datastore.AddressRefByQualifier(qualifier),
			datastore.AddressRefByType(datastore.ContractType(contractType)),
		)
		for _, r := range refs {
			if !seen[r.Address] {
				seen[r.Address] = true
				addresses = append(addresses, r.Address)
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no contracts found for qualifier %q and type %q", qualifier, contractType)
	}
	return addresses, nil
}
