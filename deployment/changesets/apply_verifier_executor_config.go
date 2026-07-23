package changesets

// ApplyVerifierExecutorConfig changeset overview
//
// ApplyVerifierExecutorConfig bundles ApplyVerifierConfig and ApplyExecutorConfig
// into a single ChangeSetV2: one deduplicated input type, one up-front validation
// pass covering both sub-flows plus the shared preconditions, one apply that runs
// both sub-flows and merges their outputs, and a combined FromState builder.
//
// It introduces zero new job-spec-generation logic: both sub-flows run entirely
// unchanged via their own public ApplyVerifierConfig() / ApplyExecutorConfig()
// ChangeSetV2 values. ApplyVerifierConfig and ApplyExecutorConfig remain public
// and are unaffected by this bundle; devenv continues to call them directly.

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const defaultQualifier = "default"

// VerifierBundleCommittee mirrors CommitteeInput but omits Qualifier: the bundle
// always resolves to defaultQualifier, so a committee-level qualifier here would
// be dead input.
type VerifierBundleCommittee struct {
	Aggregators  []AggregatorRef
	ChainConfigs map[uint64]CommitteeChainMembership
}

type VerifierBundleInput struct {
	Committee               VerifierBundleCommittee
	DisableFinalityCheckers []string
	ConsolidateAggregators  bool
}

type ExecutorBundleInput struct {
	Pool           ExecutorPoolInput
	IndexerAddress []string
}

type ApplyVerifierExecutorConfigInput struct {
	NOPs               []NOPInput
	PyroscopeURL       string
	TargetNOPs         []shared.NOPAlias
	RevokeOrphanedJobs bool
	Verifier           VerifierBundleInput
	Executor           ExecutorBundleInput
}

// deriveVerifierInput projects the combined input down to the
// ApplyVerifierConfigInput that would be handed to the standalone
// ApplyVerifierConfig changeset for the same fields.
//
// The bundle is the sole owner of the default-qualifier behavior: its input
// carries no qualifier fields at all (see ApplyVerifierExecutorConfigInput and
// VerifierBundleCommittee), and the executor side has no matching field to keep
// a custom qualifier in sync with, so both sides must always resolve to the
// same qualifier. This bundle injects defaultQualifier here rather than relying
// on the sub-changesets to default it.
func deriveVerifierInput(cfg ApplyVerifierExecutorConfigInput) ApplyVerifierConfigInput {
	return ApplyVerifierConfigInput{
		NOPs:                     cfg.NOPs,
		CommitteeQualifier:       defaultQualifier,
		DefaultExecutorQualifier: defaultQualifier,
		Committee: CommitteeInput{
			Qualifier:    defaultQualifier,
			Aggregators:  cfg.Verifier.Committee.Aggregators,
			ChainConfigs: cfg.Verifier.Committee.ChainConfigs,
		},
		PyroscopeURL:            cfg.PyroscopeURL,
		TargetNOPs:              cfg.TargetNOPs,
		DisableFinalityCheckers: cfg.Verifier.DisableFinalityCheckers,
		RevokeOrphanedJobs:      cfg.RevokeOrphanedJobs,
		ConsolidateAggregators:  cfg.Verifier.ConsolidateAggregators,
	}
}

func deriveExecutorInput(cfg ApplyVerifierExecutorConfigInput) ApplyExecutorConfigInput {
	return ApplyExecutorConfigInput{
		NOPs:               cfg.NOPs,
		ExecutorQualifier:  defaultQualifier,
		Pool:               cfg.Executor.Pool,
		IndexerAddress:     cfg.Executor.IndexerAddress,
		PyroscopeURL:       cfg.PyroscopeURL,
		TargetNOPs:         cfg.TargetNOPs,
		RevokeOrphanedJobs: cfg.RevokeOrphanedJobs,
	}
}

func ApplyVerifierExecutorConfig() deployment.ChangeSetV2[ApplyVerifierExecutorConfigInput] {
	verifierChangeset := ApplyVerifierConfig()
	executorChangeset := ApplyExecutorConfig()

	validate := func(e deployment.Environment, cfg ApplyVerifierExecutorConfigInput) error {
		var errs []error

		if err := verifierChangeset.VerifyPreconditions(e, deriveVerifierInput(cfg)); err != nil {
			errs = append(errs, fmt.Errorf("verifier: %w", err))
		}

		if err := executorChangeset.VerifyPreconditions(e, deriveExecutorInput(cfg)); err != nil {
			errs = append(errs, fmt.Errorf("executor: %w", err))
		}

		if len(cfg.NOPs) > 0 && e.Offchain == nil {
			errs = append(errs, errors.New("NOPs require JD but e.Offchain is nil"))
		}

		return errors.Join(errs...)
	}

	apply := func(e deployment.Environment, cfg ApplyVerifierExecutorConfigInput) (deployment.ChangesetOutput, error) {
		var reports []operations.Report[any, any]

		verifierOutput, err := verifierChangeset.Apply(e, deriveVerifierInput(cfg))
		reports = append(reports, verifierOutput.Reports...)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports:   reports,
				DataStore: verifierOutput.DataStore,
			}, fmt.Errorf("verifier flow failed, executor flow not attempted: %w", err)
		}

		executorOutput, err := executorChangeset.Apply(e, deriveExecutorInput(cfg))
		reports = append(reports, executorOutput.Reports...)

		executorErr := err

		ds := datastore.NewMemoryDataStore()
		if verifierOutput.DataStore != nil {
			if mergeErr := ds.Merge(verifierOutput.DataStore.Seal()); mergeErr != nil {
				return deployment.ChangesetOutput{Reports: reports}, errors.Join(fmt.Errorf("failed to merge verifier datastore: %w", mergeErr), executorErr)
			}
		}
		if executorOutput.DataStore != nil {
			if mergeErr := ds.Merge(executorOutput.DataStore.Seal()); mergeErr != nil {
				return deployment.ChangesetOutput{Reports: reports, DataStore: ds}, errors.Join(fmt.Errorf("failed to merge executor datastore: %w", mergeErr), executorErr)
			}
		}

		if executorErr != nil {
			return deployment.ChangesetOutput{
				Reports:   reports,
				DataStore: ds,
			}, fmt.Errorf("verifier flow succeeded but executor flow failed (no rollback, accepted verifier proposal left in place): %w", executorErr)
		}

		return deployment.ChangesetOutput{
			Reports:   reports,
			DataStore: ds,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
