# Topology-free deploys hand ownership to the timelock

## Executive Summary

- `DeployProtocolContracts`, `DeployCommitteeVerifier` and `OnboardChain` now transfer the deployed contracts to the timelock when `DeployerKeyOwned` is false. The transfer and acceptance come back as an MCMS timelock proposal.
- Before this change, these changesets saved only the deployed addresses. They dropped the adapter's ownership refs and `BatchOps`. A default run left every contract owned by the deployer key and still reported success. Writes the adapter deferred to MCMS were also lost.
- `DeployProtocolContractsInput` and `DeployCommitteeVerifierInput` have a new `MCMS` field. It is required when any chain has `DeployerKeyOwned` false.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `DeployProtocolContractsInput.MCMS` | added | `MCMS *ccipmcms.Input` | `deployment/changesets/deploy_protocol_contracts.go` | [#mcms-input-required](#mcms-input-required) |
| `DeployCommitteeVerifierInput.MCMS` | added | `MCMS *ccipmcms.Input` | `deployment/changesets/deploy_committee_verifier.go` | [#mcms-input-required](#mcms-input-required) |
| `DeployCommitteeVerifierPerChainCfg.DeployerKeyOwned` | added | `DeployerKeyOwned bool` | `deployment/changesets/deploy_committee_verifier.go` | [#committee-verifier-ownership](#committee-verifier-ownership) |
| `CommitteeVerifierDeployInput.DeployerKeyOwned` | added | `DeployerKeyOwned bool` | `deployment/adapters/committee_verifier_deploy.go` | [#committee-verifier-ownership](#committee-verifier-ownership) |
| `CommitteeVerifierDeployOutput.RefsToTransferOwnership` | added | `RefsToTransferOwnership` | `deployment/adapters/committee_verifier_deploy.go` | [#committee-verifier-ownership](#committee-verifier-ownership) |
| `ProtocolContractsDeployOutput.RefsToTransferOwnershipRMN` | added | `RefsToTransferOwnershipRMN` | `deployment/adapters/chain_contracts_deploy.go` | [#rmn-timelock](#rmn-timelock) |
| `DeployProtocolContracts` | behavior-changed | `func DeployProtocolContracts` | `deployment/changesets/deploy_protocol_contracts.go` | [#ownership-handover](#ownership-handover) |
| `DeployCommitteeVerifier` | behavior-changed | `func DeployCommitteeVerifier` | `deployment/changesets/deploy_committee_verifier.go` | [#committee-verifier-ownership](#committee-verifier-ownership) |
| `OnboardChain` | behavior-changed | `func OnboardChain` | `deployment/changesets/onboard_chain.go` | [#ownership-handover](#ownership-handover) |

## Breaking Changes

### MCMS input required

- `DeployProtocolContracts`, `DeployCommitteeVerifier` and `OnboardChain` fail validation when a chain has `DeployerKeyOwned` false and `MCMS` is nil. `OnboardChain` reads it from `ProtocolContracts.MCMS` and rejects a separate `CommitteeVerifiers.MCMS`.
- For those chains, validation also rejects an invalid MCMS input, a missing timelock for `MCMS.Qualifier`, and a qualifier other than `CLLCCIP` (adapters only skip contracts the CLLCCIP timelock already owns), before anything is deployed.
- A run fails when an adapter returns MCMS batch operations with transactions and `MCMS` is nil, instead of dropping them. Batch operations without transactions are ignored.
- `DeployCommitteeVerifierPerChainCfg.DeployerKeyOwned` is new and defaults to false, so a `DeployCommitteeVerifier` input that does not set it now needs `MCMS`.
- **Migration:** set `MCMS` to hand the contracts to the timelock, or set `DeployerKeyOwned` to true to keep the deployer key as owner. The devenv sets `DeployerKeyOwned` to true for both protocol contracts and committee verifiers.

## New Features / Additions

### Ownership handover

- When `DeployerKeyOwned` is false, the changeset calls `deploy.TransferToTimelock` with the adapter's `RefsToTransferOwnership`. This is the same call the chainlink-ccip `DeployChainContracts` changeset makes.
- The transfer, the acceptance and the adapter's `BatchOps` go into one timelock proposal, in that order, so the timelock owns the contracts before it runs the deferred writes. `OnboardChain` puts both phases in one proposal.
- If the handover fails, the run fails. The deployed address refs are still returned, so a retry finds the contracts instead of redeploying them.
- After the proposal executes, a re-run proposes nothing: adapters only return refs the timelock does not own yet.
- Rollback: `deploy.TransferOwnershipChangeset`, executed by the timelock.

### Committee verifier ownership

- The changeset passes `DeployerKeyOwned` to the family adapter. When it is false, the adapter returns the deployed contracts the RBAC timelock does not own yet.
- The EVM adapter reads each contract's owner on chain and compares it with the CLLCCIP timelock in `ExistingAddresses`. It fails when that timelock is missing.

### RMN timelock

- Family adapters can return `RefsToTransferOwnershipRMN` for contracts owned by the RMN timelock (qualifier `RMNMCMS`). The changeset transfers them separately. The EVM adapter now forwards this field from the EVM sequence.

## Compatibility & Requirements

- Runs with `DeployerKeyOwned` true and no deferred MCMS writes do not change.
- Family adapters outside this repository must fill `CommitteeVerifierDeployOutput.RefsToTransferOwnership` when `DeployerKeyOwned` is false. An adapter that leaves it empty keeps its verifiers with the deployer key.
- Callers of `DeployCommitteeVerifier` that keep the deployer as owner must set `DeployerKeyOwned` to true.

## References

- chainlink-ccv #1127 (topology-free deploy)
