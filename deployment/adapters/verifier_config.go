package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type VerifierContractAddresses struct {
	CommitteeVerifierAddress string
	OnRampAddress            string
	RMNRemoteAddress         string
}

// VerifierConfigAdapter resolves verifier-related on-chain addresses and the signing
// key family expected for a chain.
type VerifierConfigAdapter interface {
	// ResolveVerifierContractAddresses returns the verifier-related on-chain addresses for
	// the given chain selector. The committee and executor qualifiers identify which
	// deployments to look up in the datastore.
	ResolveVerifierContractAddresses(
		ds datastore.DataStore,
		chainSelector uint64,
		committeeQualifier string,
		executorQualifier string,
	) (*VerifierContractAddresses, error)
	// GetSignerAddressFamily returns the chain-selectors family string whose signing key
	// verifier jobs must use (e.g. chainsel.FamilyEVM for EVM committee verifiers).
	GetSignerAddressFamily() string
}

// VerifierNodeChainJDSupport is an optional extension of VerifierConfigAdapter.
// Implement it to opt out of JD node chain support validation in ApplyVerifierConfig.
// Adapters that do not implement VerifierNodeChainJDSupport default to true (require JD).
type VerifierNodeChainJDSupport interface {
	// RequiresNodeChainSupportInJD reports whether ApplyVerifierConfig must verify that
	// target NOPs have this chain registered in JD (ListNodeChainConfigs) before proposing
	// ccvcommitteeverifier job specs. EVM chains require JD registration; families such as
	// Solana whose standalone verifiers do not report chain configs to JD may return false.
	RequiresNodeChainSupportInJD() bool
}

// VerifierRequiresNodeChainSupportInJD returns whether the adapter requires JD node chain
// support validation. Adapters without VerifierNodeChainJDSupport default to true.
func VerifierRequiresNodeChainSupportInJD(adapter VerifierConfigAdapter) bool {
	if a, ok := adapter.(VerifierNodeChainJDSupport); ok {
		return a.RequiresNodeChainSupportInJD()
	}
	return true
}
