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

// ApplyOnrampRedeployVerifierConfig publishes or refreshes temporary verifier
// job specs used during an OnRamp redeployment.
//
// Unlike the canonical verifier jobs, these jobs:
//   - target only the chains currently undergoing an upgrade;
//   - use the legacy OnRamp address for those chains; and
//   - use a distinct job suffix to avoid conflicting with canonical jobs.
//
// No onchain state is touched and no MCMS coordination is required.
func ApplyOnrampRedeployVerifierConfig(
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
			WithJobSuffix(jobSuffix),
			WithSelectorFilter(cfg.UpgradedChainSelectors...),
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
