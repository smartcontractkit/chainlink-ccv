# Protocol contract deploys hand ownership to the timelock

## Executive Summary

- `DeployProtocolContracts` and `OnboardChain` now transfer the deployed protocol contracts to the timelock when `DeployerKeyOwned` is false. The transfer and acceptance come back as an MCMS timelock proposal.
- Before this change, both changesets saved only the deployed addresses. They dropped `RefsToTransferOwnership` and `BatchOps` from the family adapter. A default run left every contract owned by the deployer key and still reported success. Writes the adapter deferred to MCMS were also lost.
- `DeployProtocolContractsInput` has a new `MCMS` field. It is required when any chain has `DeployerKeyOwned` false.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `DeployProtocolContractsInput.MCMS` | added | `MCMS *ccipmcms.Input` | `deployment/changesets/deploy_protocol_contracts.go` | [#mcms-input-required](#mcms-input-required) |
| `ProtocolContractsDeployOutput.RefsToTransferOwnershipRMN` | added | `RefsToTransferOwnershipRMN` | `deployment/adapters/chain_contracts_deploy.go` | [#rmn-timelock](#rmn-timelock) |
| `DeployProtocolContracts` | behavior-changed | `func DeployProtocolContracts` | `deployment/changesets/deploy_protocol_contracts.go` | [#ownership-handover](#ownership-handover) |
| `OnboardChain` | behavior-changed | `func OnboardChain` | `deployment/changesets/onboard_chain.go` | [#ownership-handover](#ownership-handover) |

## Breaking Changes

### MCMS input required

- `DeployProtocolContracts` and `OnboardChain` fail validation when a chain has `DeployerKeyOwned` false and `DeployProtocolContractsInput.MCMS` is nil. `OnboardChain` reads it from `ProtocolContracts.MCMS`.
- **Migration:** set `MCMS` to hand the contracts to the timelock, or set `DeployerKeyOwned` to true to keep the deployer key as owner. The devenv already sets `DeployerKeyOwned` to true and needs no change.

## New Features / Additions

### Ownership handover

- When `DeployerKeyOwned` is false, the changeset calls `deploy.TransferToTimelock` with the adapter's `RefsToTransferOwnership`. This is the same call the chainlink-ccip `DeployChainContracts` changeset makes.
- The adapter's `BatchOps`, the transfer and the acceptance go into one timelock proposal. `OnboardChain` also adds the committee verifier batch operations to that proposal.
- If the handover fails, the run fails.

### RMN timelock

- Family adapters can return `RefsToTransferOwnershipRMN` for contracts owned by the RMN timelock (qualifier `RMNMCMS`). The changeset transfers them separately. The EVM adapter now forwards this field from the EVM sequence.

## Compatibility & Requirements

- Runs with `DeployerKeyOwned` true do not change.
- The standalone `DeployCommitteeVerifier` still has no MCMS input and does not put its batch operations in a proposal (CCIP-11432).

## References

- chainlink-ccv #1127 (topology-free deploy)
