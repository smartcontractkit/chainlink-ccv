# Topology-free deploys hand ownership to the timelock

## Executive Summary

- `DeployProtocolContracts`, `DeployCommitteeVerifier` and `OnboardChain` transfer the deployed contracts to the CLLCCIP timelock when `DeployerKeyOwned` is false, and return the transfer, the acceptance and the adapter's deferred writes as one MCMS timelock proposal.
- Before this change they kept only the deployed addresses: they dropped the adapter's ownership refs and `BatchOps`, so a default run left every contract with the deployer key and still reported success, and writes deferred to MCMS were lost.
- Affects callers of the three changesets and every `CommitteeVerifierDeployAdapter` and `ProtocolContractsDeployAdapter` implementation.
- Breaking: `DeployCommitteeVerifierPerChainCfg.DeployerKeyOwned` is new and defaults to false, so a `DeployCommitteeVerifier` input that does not set it now needs `MCMS`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.DeployCommitteeVerifier` | behavior-changed | `\bDeployCommitteeVerifier\(\)` | `deployment/changesets/deploy_committee_verifier.go:80` | [#committee-verifiers-default-to-the-timelock](#committee-verifiers-default-to-the-timelock) |
| `changesets.DeployProtocolContracts` | behavior-changed | `\bDeployProtocolContracts\(\)` | `deployment/changesets/deploy_protocol_contracts.go:98` | [#handover-requires-an-mcms-input](#handover-requires-an-mcms-input) |
| `changesets.OnboardChain` | behavior-changed | `\bOnboardChain\(\)` | `deployment/changesets/onboard_chain.go:57` | [#handover-requires-an-mcms-input](#handover-requires-an-mcms-input) |
| `adapters.CommitteeVerifierDeployAdapter` | behavior-changed | `CommitteeVerifierDeployAdapter\b` | `deployment/adapters/committee_verifier_deploy.go:43` | [#adapters-list-committee-verifiers-to-hand-over](#adapters-list-committee-verifiers-to-hand-over) |
| `changesets.DeployCommitteeVerifierPerChainCfg.DeployerKeyOwned` | added | `DeployCommitteeVerifierPerChainCfg\{` | `deployment/changesets/deploy_committee_verifier.go:25` | [#committee-verifiers-default-to-the-timelock](#committee-verifiers-default-to-the-timelock) |
| `changesets.DeployCommitteeVerifierInput.MCMS` | added | `DeployCommitteeVerifierInput\{` | `deployment/changesets/deploy_committee_verifier.go:50` | [#handover-requires-an-mcms-input](#handover-requires-an-mcms-input) |
| `changesets.DeployProtocolContractsInput.MCMS` | added | `DeployProtocolContractsInput\{` | `deployment/changesets/deploy_protocol_contracts.go:67` | [#handover-requires-an-mcms-input](#handover-requires-an-mcms-input) |
| `adapters.CommitteeVerifierDeployInput.DeployerKeyOwned` | added | `CommitteeVerifierDeployInput\{` | `deployment/adapters/committee_verifier_deploy.go:43` | [#adapters-list-committee-verifiers-to-hand-over](#adapters-list-committee-verifiers-to-hand-over) |
| `adapters.CommitteeVerifierDeployOutput.RefsToTransferOwnership` | added | `CommitteeVerifierDeployOutput\{` | `deployment/adapters/committee_verifier_deploy.go:54` | [#adapters-list-committee-verifiers-to-hand-over](#adapters-list-committee-verifiers-to-hand-over) |
| `adapters.ProtocolContractsDeployOutput.RefsToTransferOwnershipRMN` | added | `ProtocolContractsDeployOutput\{` | `deployment/adapters/chain_contracts_deploy.go:54` | [#rmn-timelock-handover](#rmn-timelock-handover) |

## Breaking Changes

### Committee verifiers default to the timelock

- **What changed:** `DeployCommitteeVerifierPerChainCfg` has a new `DeployerKeyOwned` field, and the changeset hands the verifiers to the timelock when it is false.
- **Before:** `DeployCommitteeVerifier` always left the verifiers with the deployer key and had no MCMS input.
- **After:** with the zero value (`false`), verify requires `DeployCommitteeVerifierInput.MCMS` and a CLLCCIP timelock in the datastore; apply transfers the verifiers and returns a proposal.
- **Why:** matches `DeployProtocolContracts` and the chainlink-ccip `DeployChainContracts` changeset, where false means the timelock owns the contracts.
- **Who is affected:** every caller that builds `DeployCommitteeVerifierInput` without setting `DeployerKeyOwned`, including environments without MCMS.

### Handover requires an MCMS input

- **What changed:** `DeployProtocolContracts`, `DeployCommitteeVerifier` and `OnboardChain` validate the handover before deploying and fail instead of dropping MCMS writes.
- **Before:** with `DeployerKeyOwned` false they reported success, left the contracts with the deployer key and dropped the adapter's `BatchOps`.
- **After:** for a chain with `DeployerKeyOwned` false, verify rejects a nil or invalid `MCMS`, a missing timelock for `MCMS.Qualifier`, and a qualifier other than `CLLCCIP`. Apply fails when an adapter returns batch operations with transactions and `MCMS` is nil; batch operations without transactions are ignored. `OnboardChain` reads `ProtocolContracts.MCMS` and rejects `CommitteeVerifiers.MCMS`.
- **Why:** a run must not report success while the contracts stay with the deployer key or writes are lost. Adapters only skip contracts the CLLCCIP timelock already owns, so another qualifier would re-propose the handover on every run.
- **Who is affected:** callers of the three changesets that leave `DeployerKeyOwned` false.

## Migration Guide

1. Find every `DeployCommitteeVerifierInput{`, `DeployProtocolContractsInput{` and `OnboardChainInput{` literal.
2. If the deployer key must keep ownership (no MCMS on the chain), set `DeployerKeyOwned: true` in `DefaultCfg` or in each `ChainCfgs` entry.
3. Otherwise set `MCMS` (for `OnboardChain`, `ProtocolContracts.MCMS` only) with an empty qualifier or `CLLCCIP`.
4. In a `CommitteeVerifierDeployAdapter`, when `input.DeployerKeyOwned` is false, return in `RefsToTransferOwnership` the deployed contracts the CLLCCIP timelock does not own yet.

```go
// Before: deployer-owned implicitly
ccvchangesets.DeployCommitteeVerifierInput{
	ChainSelectors: []uint64{sel},
	Committees:     committees,
	DefaultCfg:     ccvchangesets.DeployCommitteeVerifierPerChainCfg{DeployerContract: factory},
}
```

```go
// After: deployer-owned explicitly
ccvchangesets.DeployCommitteeVerifierInput{
	ChainSelectors: []uint64{sel},
	Committees:     committees,
	DefaultCfg: ccvchangesets.DeployCommitteeVerifierPerChainCfg{
		DeployerContract: factory,
		DeployerKeyOwned: true,
	},
}
```

```go
// After: handed to the CLLCCIP timelock
ccvchangesets.DeployCommitteeVerifierInput{
	ChainSelectors: []uint64{sel},
	Committees:     committees,
	DefaultCfg:     ccvchangesets.DeployCommitteeVerifierPerChainCfg{DeployerContract: factory},
	MCMS:           &mcmsutil.Input{TimelockAction: mcmstypes.TimelockActionSchedule},
}
```

## New Features / Additions

### Adapters list committee verifiers to hand over

- **`CommitteeVerifierDeployInput.DeployerKeyOwned` / `CommitteeVerifierDeployOutput.RefsToTransferOwnership`** — the changeset tells the adapter whether to keep the deployer as owner, and the adapter returns the contracts the timelock does not own yet. See `deployment/adapters/committee_verifier_deploy.go:43`.
  - The EVM adapter reads each contract's owner on chain and fails when the CLLCCIP timelock is missing (`integration/evm/adapters/committee_verifier_deploy_adapter.go:145`). An adapter that leaves the field empty keeps its verifiers with the deployer key.

### RMN timelock handover

- **`ProtocolContractsDeployOutput.RefsToTransferOwnershipRMN`** — contracts owned by the RMNMCMS timelock instead of CLLCCIP; the changeset transfers them separately. The EVM adapter forwards it from the EVM sequence (`integration/evm/adapters/protocol_contracts_deploy_adapter.go:111`).

### Proposal contents

- **One proposal per run** — the transfer and acceptance come first, then the adapter's deferred writes, so the timelock owns the contracts before it runs them. After the proposal executes, a re-run proposes nothing.
  - If the handover fails, the deployed refs are still returned so a retry finds the contracts. Rollback: `deploy.TransferOwnershipChangeset`, executed by the timelock.

## Compatibility & Requirements

- **Supported environments / chains:** runs with `DeployerKeyOwned` true and no deferred MCMS writes behave as before. The devenv sets `DeployerKeyOwned` to true for protocol contracts and committee verifiers (`build/devenv/components/committeeccv/component.go:416`).

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1650
- Prior work this builds on: chainlink-ccv #1127 (topology-free deploy)
