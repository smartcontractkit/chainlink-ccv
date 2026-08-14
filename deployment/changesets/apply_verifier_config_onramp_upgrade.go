package changesets

import (
	"errors"
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

type ApplyVerifierConfigOnrampUpgradeInput struct {
	UpgradedChainSelectors []uint64
	ApplyVerifierConfigInput
}

const (
	jobSuffix = "-temp-onramp-upgrade"
)

// ApplyOnrampRedeployVerifierConfig is the offchain-only single-entry product for §5.9 / §5.10:
// publish or refresh verifier job specs for a committee. It writes new job specs
// via JD (CL-mode NOPs) and persists job metadata into the DataStore. No onchain
// state is touched and no MCMS coordination is required.
//
// The input is imperative — callers pass the committee description and the
// participating NOPs directly, with no *EnvironmentTopology.
//
// This changeset is not publishing the canonical verifier job specs, but rather a temporary job spec that overrides the OnRamp address for redeployed chains.
// It reads the legacy OnRamp address from the DataStore and uses it to override the new OnRamp address in the verifier job spec for redeployed chains.
// It also target a subset of the chains only the chains that have an upgrade (sent as input)
// Finally the job spec is suffixed with "-temp-onramp-upgrade" to avoid conflicts with the canonical job spec.
func ApplyOnrampRedeployVerifierConfig(onrampUpgraderRegistry *adapters.OnRampUpgraderRegistry) deployment.ChangeSetV2[ApplyVerifierConfigOnrampUpgradeInput] {

	apply := func(e deployment.Environment, cfg ApplyVerifierConfigOnrampUpgradeInput) (deployment.ChangesetOutput, error) {
		onrampOverrides := make(map[string]string)
		// For each redeployed chain selector, we need to find the legacy OnRamp address
		// For this temp job we will use the legacy OnRamp address to override the new OnRamp address in the verifier job spec
		for _, selector := range cfg.UpgradedChainSelectors {
			family, err := chainsel.GetSelectorFamily(selector)
			if err != nil {
				return deployment.ChangesetOutput{}, err
			}
			redeployer, ok := onrampUpgraderRegistry.Get(family)
			if !ok {
				return deployment.ChangesetOutput{}, errors.New("no redeployer registered for chain family: " + family)
			}
			legacyOnrampRef, err := redeployer.LegacyOnRampRef(e, selector)
			if err != nil {
				continue // skip this selector if we can't find the legacy OnRamp address
			}
			onrampOverrides[fmt.Sprint(selector)] = legacyOnrampRef.Address
		}
		return createApplyVerifierConfigApplyFunc(
			WithDifferentOnramp(onrampOverrides),
			WithJobSuffix(jobSuffix),
			WithSelectorFilter(cfg.UpgradedChainSelectors...),
		)(e, cfg.ApplyVerifierConfigInput)
	}

	validate := func(e deployment.Environment, cfg ApplyVerifierConfigOnrampUpgradeInput) error {
		if len(cfg.UpgradedChainSelectors) == 0 {
			return errors.New("at least one redeployed chain selector is required")
		}
		return createApplyVerifierConfigValidateFunc()(e, cfg.ApplyVerifierConfigInput)
	}

	return deployment.CreateChangeSet(apply, validate)
}
