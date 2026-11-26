package changesets

import (
	"errors"
	"fmt"
	"slices"

	chainsel "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	ccipcommon "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	ccipchangesets "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccipmcms "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// Variables so tests can stub the on-chain handover and the timelock lookup.
var (
	transferToTimelock = deploy.TransferToTimelock
	mcmsReaders        = ccipchangesets.GetRegistry
)

// deployResult carries what a deploy helper produced, including on error.
type deployResult struct {
	Reports  []operations.Report[any, any]
	BatchOps []mcmstypes.BatchOperation
}

// DeployProtocolContractsPerChainCfg carries the per-chain configuration for
// deploying CCIP protocol contracts (RMN, OnRamp, OffRamp, FeeQuoter, Router,
// Executors). Committee verifiers are deployed separately.
type DeployProtocolContractsPerChainCfg struct {
	// DeployerContract is the deployer/factory address (e.g. CREATE2Factory on EVM).
	DeployerContract string
	// DeployTestRouter deploys a TestRouter alongside the production Router.
	DeployTestRouter bool
	// Executors lists executor instances to deploy.
	Executors []adapters.ExecutorDeployParams
	// DeployerKeyOwned when true means deployed contracts remain owned by the
	// deployer key. When false (the default), the changeset transfers ownership
	// to the RBAC timelock (and RMN contracts to the RMN timelock) and returns
	// the acceptance as an MCMS proposal; DeployProtocolContractsInput.MCMS is
	// then required.
	DeployerKeyOwned bool
	// FamilyExtras carries chain-family-specific deploy parameters.
	FamilyExtras map[string]any
}

// DeployProtocolContractsInput is the imperative input for the
// DeployProtocolContracts changeset.
type DeployProtocolContractsInput struct {
	// ChainSelectors are the chains to deploy on.
	ChainSelectors []uint64
	// DefaultCfg supplies fallback per-chain values. Used when a chain has no
	// entry in ChainCfgs.
	DefaultCfg DeployProtocolContractsPerChainCfg
	// ChainCfgs overrides DefaultCfg for specific chains.
	ChainCfgs map[uint64]DeployProtocolContractsPerChainCfg
	// MCMS configures the timelock proposal that carries the ownership handover
	// and any writes the adapter deferred to MCMS. Required when any chain has
	// DeployerKeyOwned false.
	MCMS *ccipmcms.Input
}

func (c DeployProtocolContractsInput) mcmsInput() ccipmcms.Input {
	if c.MCMS == nil {
		return ccipmcms.Input{}
	}
	return *c.MCMS
}

func (c DeployProtocolContractsInput) resolveChainCfg(sel uint64) DeployProtocolContractsPerChainCfg {
	if override, ok := c.ChainCfgs[sel]; ok {
		return override
	}
	return c.DefaultCfg
}

// DeployProtocolContracts is a single-entry, onchain-only changeset that
// deploys the core CCIP protocol contracts (RMN, OnRamp, OffRamp, FeeQuoter,
// Router, Executors) on the specified chains.
//
// Committee verifiers are NOT deployed by this changeset — use
// DeployCommitteeVerifier for that, or OnboardChain for both in one pass.
//
// For a chain with DeployerKeyOwned false, the timelock for MCMS.Qualifier must
// be in the datastore, plus the RMNMCMS timelock if the family adapter returns
// RMN refs. The output is the deployed address refs and one timelock proposal
// with the ownership acceptance and the writes the adapter deferred to MCMS.
// Once that proposal executes, a re-run proposes nothing: adapters only return
// refs the timelock does not own yet. Rollback: deploy.TransferOwnershipChangeset
// executed by the timelock.
func DeployProtocolContracts() deployment.ChangeSetV2[DeployProtocolContractsInput] {
	validate := func(e deployment.Environment, cfg DeployProtocolContractsInput) error {
		return validateProtocolContractsDeploy(e, cfg)
	}

	apply := func(e deployment.Environment, cfg DeployProtocolContractsInput) (deployment.ChangesetOutput, error) {
		ds := datastore.NewMemoryDataStore()
		res, err := deployProtocolContractsOnChains(e, cfg, ds)
		if err == nil {
			err = requireMCMSForBatchOps(res.BatchOps, cfg.MCMS)
		}
		if err != nil {
			return deployment.ChangesetOutput{Reports: res.Reports, DataStore: ds}, err
		}
		return ccipchangesets.NewOutputBuilder(e, mcmsReaders()).
			WithReports(res.Reports).
			WithBatchOps(res.BatchOps).
			WithDataStore(ds).
			Build(cfg.mcmsInput())
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateProtocolContractsDeploy validates the input for protocol contract deployment.
func validateProtocolContractsDeploy(e deployment.Environment, cfg DeployProtocolContractsInput) error {
	if len(cfg.ChainSelectors) == 0 {
		return errors.New("at least one chain selector is required")
	}

	envSelectors := e.BlockChains.ListChainSelectors()
	seen := make(map[uint64]bool, len(cfg.ChainSelectors))
	for _, sel := range cfg.ChainSelectors {
		if seen[sel] {
			return fmt.Errorf("duplicate chain selector %d in ChainSelectors", sel)
		}
		seen[sel] = true
		if !slices.Contains(envSelectors, sel) {
			return fmt.Errorf("chain selector %d is not available in environment", sel)
		}
		chainCfg := cfg.resolveChainCfg(sel)
		if chainCfg.DeployerContract == "" {
			return fmt.Errorf("DeployerContract is required for chain %d", sel)
		}
		if !chainCfg.DeployerKeyOwned {
			if err := validateTimelockHandover(e, sel, cfg.MCMS); err != nil {
				return err
			}
		}
		if _, err := adapters.GetProtocolContractsDeployRegistry().Get(sel); err != nil {
			return fmt.Errorf("chain %d: %w", sel, err)
		}
	}

	for sel := range cfg.ChainCfgs {
		if !slices.Contains(cfg.ChainSelectors, sel) {
			return fmt.Errorf("ChainCfgs contains selector %d which is not in ChainSelectors", sel)
		}
	}

	return nil
}

// requireMCMSForBatchOps fails a run whose adapters deferred writes to MCMS
// when there is no MCMS input to propose them with. Batch ops without
// transactions are ignored, as OutputBuilder drops them.
func requireMCMSForBatchOps(batchOps []mcmstypes.BatchOperation, mcmsInput *ccipmcms.Input) error {
	if mcmsInput != nil {
		return nil
	}
	pending := 0
	for _, op := range batchOps {
		if len(op.Transactions) > 0 {
			pending++
		}
	}
	if pending > 0 {
		return fmt.Errorf("adapters returned %d MCMS batch operations but no MCMS input is set", pending)
	}
	return nil
}

// validateTimelockHandover checks, before anything is deployed, that the
// proposal input is valid and the timelock receiving ownership exists.
func validateTimelockHandover(e deployment.Environment, sel uint64, mcmsInput *ccipmcms.Input) error {
	if mcmsInput == nil {
		return fmt.Errorf("MCMS input is required for chain %d: ownership is transferred to the timelock unless DeployerKeyOwned is set", sel)
	}
	proposal := *mcmsInput
	if err := proposal.PopulateDefaults(); err != nil {
		return fmt.Errorf("chain %d: %w", sel, err)
	}
	if err := proposal.Validate(); err != nil {
		return fmt.Errorf("chain %d: %w", sel, err)
	}
	family, err := chainsel.GetSelectorFamily(sel)
	if err != nil {
		return fmt.Errorf("chain %d: %w", sel, err)
	}
	reader, ok := mcmsReaders().GetMCMSReader(family)
	if !ok {
		return fmt.Errorf("chain %d: no MCMS reader registered for family %s", sel, family)
	}
	// Readers default an empty qualifier to CLLCCIP and return an empty ref, not an
	// error, when the timelock is missing.
	qualifier := proposal.Qualifier
	if qualifier == "" {
		qualifier = ccipcommon.CLLQualifier
	}
	// Adapters skip contracts the CLLCCIP timelock already owns. Handing them to
	// another timelock would be proposed again on every run.
	if qualifier != ccipcommon.CLLQualifier {
		return fmt.Errorf("chain %d: ownership can only be handed to the %s timelock, got MCMS qualifier %q",
			sel, ccipcommon.CLLQualifier, qualifier)
	}
	timelock, err := reader.GetTimelockRef(e, sel, proposal)
	if err != nil {
		return fmt.Errorf("chain %d: resolve timelock for MCMS qualifier %q: %w", sel, qualifier, err)
	}
	if timelock.Address == "" {
		return fmt.Errorf("chain %d: no timelock for MCMS qualifier %q (deploy MCMS first, or check mcms.qualifier)", sel, qualifier)
	}
	return nil
}

// deployProtocolContractsOnChains deploys protocol contracts on every chain in
// cfg, writes deployed addresses to ds and hands the contracts to the timelock
// unless DeployerKeyOwned is set. The returned batch ops belong in one MCMS
// proposal. This is the shared core used by both DeployProtocolContracts and
// OnboardChain.
func deployProtocolContractsOnChains(
	e deployment.Environment,
	cfg DeployProtocolContractsInput,
	ds datastore.MutableDataStore,
) (deployResult, error) {
	var res deployResult

	for _, sel := range cfg.ChainSelectors {
		chainCfg := cfg.resolveChainCfg(sel)

		deployer, err := adapters.GetProtocolContractsDeployRegistry().Get(sel)
		if err != nil {
			return res, fmt.Errorf("chain %d: %w", sel, err)
		}

		existingAddresses := e.DataStore.Addresses().Filter(
			datastore.AddressRefByChainSelector(sel),
		)

		input := adapters.ProtocolContractsDeployInput{
			ChainSelector:     sel,
			DeployerContract:  chainCfg.DeployerContract,
			DeployTestRouter:  chainCfg.DeployTestRouter,
			ExistingAddresses: existingAddresses,
			Executors:         chainCfg.Executors,
			DeployerKeyOwned:  chainCfg.DeployerKeyOwned,
			FamilyExtras:      chainCfg.FamilyExtras,
		}

		e.Logger.Infow("Deploying protocol contracts",
			"chain", sel,
			"deployTestRouter", chainCfg.DeployTestRouter,
			"executorCount", len(chainCfg.Executors),
		)

		report, err := operations.ExecuteSequence(
			e.OperationsBundle,
			deployer.DeployProtocolContracts(),
			e.BlockChains,
			input,
		)
		res.Reports = append(res.Reports, report.ExecutionReports...)
		if err != nil {
			return res, fmt.Errorf("chain %d: deploy failed: %w", sel, err)
		}
		// Record the deployed refs before the handover so a failed handover can be retried
		// without redeploying.
		for _, ref := range report.Output.Addresses {
			if addErr := ds.Addresses().Add(ref); addErr != nil &&
				!errors.Is(addErr, datastore.ErrAddressRefExists) {
				return res, fmt.Errorf("chain %d: failed to add %s %s at %s to datastore: %w",
					sel, ref.Type, ref.Version, ref.Address, addErr)
			}
		}

		if !chainCfg.DeployerKeyOwned {
			handover, transferErr := transferToTimelocks(e, sel, cfg.mcmsInput(),
				report.Output.RefsToTransferOwnership, report.Output.RefsToTransferOwnershipRMN)
			res.Reports = append(res.Reports, handover.Reports...)
			if transferErr != nil {
				return res, fmt.Errorf("chain %d: %w", sel, transferErr)
			}
			res.BatchOps = append(res.BatchOps, handover.BatchOps...)
		}
		// The timelock accepts ownership before running the writes deferred to it.
		res.BatchOps = append(res.BatchOps, report.Output.BatchOps...)
	}

	return res, nil
}

// transferToTimelocks transfers refs to the RBAC timelock and rmnRefs to the RMN
// timelock.
func transferToTimelocks(
	e deployment.Environment,
	sel uint64,
	mcmsInput ccipmcms.Input,
	refs, rmnRefs []datastore.AddressRef,
) (deployResult, error) {
	rmnInput := mcmsInput
	rmnInput.Qualifier = ccipcommon.RMNTimelockQualifier
	handovers := []struct {
		name  string
		input ccipmcms.Input
		refs  []datastore.AddressRef
	}{
		{name: "timelock", input: mcmsInput, refs: refs},
		{name: "RMN timelock", input: rmnInput, refs: rmnRefs},
	}

	var res deployResult
	for _, h := range handovers {
		if len(h.refs) == 0 {
			continue
		}
		ops, reports, err := transferToTimelock(sel, e, h.input, h.refs,
			mcmsReaders(), deploy.GetTransferOwnershipRegistry())
		res.Reports = append(res.Reports, reports...)
		if err != nil {
			return res, fmt.Errorf("failed to transfer ownership to %s: %w", h.name, err)
		}
		res.BatchOps = append(res.BatchOps, ops...)
	}
	return res, nil
}

// deployCommitteeVerifiersOnChains deploys committee verifiers on every chain
// in cfg, writes deployed addresses to ds and hands the verifiers to the
// timelock unless DeployerKeyOwned is set. This is the shared core used by both
// DeployCommitteeVerifier and OnboardChain.
func deployCommitteeVerifiersOnChains(
	e deployment.Environment,
	cfg DeployCommitteeVerifierInput,
	ds datastore.MutableDataStore,
) (deployResult, error) {
	var res deployResult

	for _, sel := range cfg.ChainSelectors {
		deployer, err := adapters.GetCommitteeVerifierDeployRegistry().Get(sel)
		if err != nil {
			return res, fmt.Errorf("chain %d: %w", sel, err)
		}

		chainCfg := cfg.resolveChainCfg(sel)
		existingAddresses := e.DataStore.Addresses().Filter(
			datastore.AddressRefByChainSelector(sel),
		)
		var toTransfer []datastore.AddressRef
		var deferred []mcmstypes.BatchOperation

		for _, committee := range cfg.Committees {
			input := adapters.CommitteeVerifierDeployInput{
				ChainSelector:     sel,
				DeployerContract:  chainCfg.DeployerContract,
				ExistingAddresses: existingAddresses,
				Params:            committee,
				DeployerKeyOwned:  chainCfg.DeployerKeyOwned,
			}

			e.Logger.Infow("Deploying CommitteeVerifier",
				"chain", sel,
				"committee", committee.Qualifier,
			)

			report, err := operations.ExecuteSequence(
				e.OperationsBundle,
				deployer.DeployCommitteeVerifier(),
				e.BlockChains,
				input,
			)
			res.Reports = append(res.Reports, report.ExecutionReports...)
			if err != nil {
				return res, fmt.Errorf("chain %d committee %q: deploy failed: %w", sel, committee.Qualifier, err)
			}
			deferred = append(deferred, report.Output.BatchOps...)
			toTransfer = append(toTransfer, report.Output.RefsToTransferOwnership...)

			for _, ref := range report.Output.Addresses {
				if addErr := ds.Addresses().Add(ref); addErr != nil &&
					!errors.Is(addErr, datastore.ErrAddressRefExists) {
					return res, fmt.Errorf("chain %d committee %q: failed to add %s %s at %s to datastore: %w",
						sel, committee.Qualifier, ref.Type, ref.Version, ref.Address, addErr)
				}
				existingAddresses = append(existingAddresses, ref)
			}
		}

		if !chainCfg.DeployerKeyOwned {
			handover, transferErr := transferToTimelocks(e, sel, cfg.mcmsInput(), toTransfer, nil)
			res.Reports = append(res.Reports, handover.Reports...)
			if transferErr != nil {
				return res, fmt.Errorf("chain %d: %w", sel, transferErr)
			}
			res.BatchOps = append(res.BatchOps, handover.BatchOps...)
		}
		res.BatchOps = append(res.BatchOps, deferred...)
	}

	return res, nil
}
