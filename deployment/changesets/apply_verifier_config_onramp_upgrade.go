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

const jobSuffix = "temp-onramp-upgrade"

// ApplyOnrampUpgradeVerifierConfig publishes or refreshes temporary verifier
// job specs used during an OnRamp redeployment.
//
// The temporary jobs retain the complete committee chain configuration so they
// continue verifying traffic from every committee chain while an upgrade is in
// progress. For chains listed in UpgradedChainSelectors, the canonical OnRamp
// address is replaced with the legacy OnRamp address.
//
// The temporary jobs use a distinct job suffix to avoid conflicting with the
// canonical verifier jobs.
//
// No onchain state is touched and no MCMS coordination is required.
func ApplyOnrampUpgradeVerifierConfig(
	onrampUpgraderRegistry *adapters.OnRampUpgraderRegistry,
) deployment.ChangeSetV2[ApplyVerifierConfigOnrampUpgradeInput] {
	apply := func(
		e deployment.Environment,
		cfg ApplyVerifierConfigOnrampUpgradeInput,
	) (deployment.ChangesetOutput, error) {
		onrampOverrides := make(map[string]string, len(cfg.UpgradedChainSelectors))

		for _, selector := range cfg.UpgradedChainSelectors {
			if _, ok := cfg.Committee.ChainConfigs[selector]; !ok {
				return deployment.ChangesetOutput{}, fmt.Errorf(
					"upgraded chain %d is not configured for committee %q",
					selector,
					cfg.CommitteeQualifier,
				)
			}

			family, err := chainsel.GetSelectorFamily(selector)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf(
					"get chain family for upgraded chain %d: %w",
					selector,
					err,
				)
			}

			redeployer, ok := onrampUpgraderRegistry.Get(family)
			if !ok {
				return deployment.ChangesetOutput{}, errors.New(
					"no redeployer registered for chain family: " + family,
				)
			}

			legacyOnrampRef, err := redeployer.LegacyOnRampRef(e, selector)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf(
					"get legacy OnRamp for upgraded chain %d: %w",
					selector,
					err,
				)
			}

			onrampOverrides[fmt.Sprint(selector)] = legacyOnrampRef.Address
		}

		return createApplyVerifierConfigApplyFunc(
			WithDifferentOnramp(onrampOverrides),
			WithIsolatedJob(jobSuffix),
		)(e, cfg.ApplyVerifierConfigInput)
	}

	validate := func(
		e deployment.Environment,
		cfg ApplyVerifierConfigOnrampUpgradeInput,
	) error {
		if len(cfg.UpgradedChainSelectors) == 0 {
			return errors.New("at least one upgraded chain selector is required")
		}

		if err := createApplyVerifierConfigValidateFunc()(
			e,
			cfg.ApplyVerifierConfigInput,
		); err != nil {
			return err
		}

		for _, selector := range cfg.UpgradedChainSelectors {
			if _, ok := cfg.Committee.ChainConfigs[selector]; !ok {
				return fmt.Errorf(
					"upgraded chain %d is not configured for committee %q",
					selector,
					cfg.CommitteeQualifier,
				)
			}
		}

		return nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
