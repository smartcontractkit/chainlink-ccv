# Split protocol-contract and committee-verifier deploys across phases

Splits the devenv's single chainlink-ccip "kitchen-sink" `DeployChainContracts`
into per-phase ccv changesets, and bumps `chainlink-ccip` to `3600f66e26cd`
(`2026-06-18`), which provides the EVM `ProtocolContractsDeployAdapter`.

---

## New: `[protocol_contracts.deploy]` config section

Per-chain protocol-contract deploy tunables are now configured in TOML instead of
hard-coded in Go:

```toml
[protocol_contracts.deploy]
deploy_test_router = false

[[protocol_contracts.deploy.executors]]
qualifier = "default"
version = "2.0.0"

[[protocol_contracts.deploy.executors]]
qualifier = "custom"
version = "2.0.0"

[protocol_contracts.deploy.family_extras]
feeAggregator = "0x..."   # EVM: applied to the OnRamp and executor proxies
```

When `executors` is omitted it defaults to `default` + `custom` at `2.0.0`. On EVM,
`family_extras` accepts `feeAggregator`, `executorBlockDepth`, and
`executorWaitForSafe`; unset fields use the adapter defaults (`BlockDepth: 1`,
`MaxCCVsPerMsg: 10`). Setting `executorWaitForSafe = true` is required for
wait-for-safe finality smoke tests.

---

## Changed: committee verifiers and mock receivers deploy in Phase 3

Phase 2 (`protocol_contracts`) now deploys only the core protocol contracts via the
ccv `DeployProtocolContracts` changeset. Committee verifiers and their resolvers
deploy in Phase 3 (`committeeccv`) via `DeployCommitteeVerifier`, followed by mock
receivers and token-transfer configuration — both depend on the resolver. USDC and
Lombard token *pools* continue to deploy in Phase 2.

---

## New: optional `MockReceiverDeployer` interface

`cciptestinterfaces.MockReceiverDeployer` is an optional interface. Chain families
that implement it deploy mock receivers in Phase 3, after the committee-verifier
resolver exists; families that do not implement it deploy no receivers.

---

## Bug fix: CCTP and Lombard mock receivers in the monolith path

`DeployContractsForSelector` (the monolith `standard.profile` path) now calls
`DeployMockReceivers` via the `MockReceiverDeployer` hook after committee verifiers
and token pools are deployed. Previously the USDC/CCTP and Lombard mock receivers
were deployed inline during token-pool setup, before the committee-verifier resolver
existed, causing `TestE2ESmoke_TokenVerification` to fail.

---

## New: phase-3 contract addresses persisted to env-out.toml

Committee verifiers and mock receivers deployed in Phase 3 are now appended to the
CLDF accumulator and serialised to `env-*-out.toml` alongside the Phase 2 protocol
contracts. Previously these addresses were only in the merged in-memory datastore
and were missing from the saved output file.

---

## Dependency: chainlink-ccip bumped to provide the deploy adapter

`chainlink-ccip/chains/evm` and `chainlink-ccip/deployment` are bumped to
`3600f66e26cd` (`2026-06-18`), which registers the EVM
`ProtocolContractsDeployAdapter` in its `init()`. The temporary in-repo wrapper
(`build/devenv/evm/protocol_contracts_deploy_adapter.go`) is removed. The bump also
changes the `DeployChainContracts` changeset to take a `ChainFamilyRegistry`
argument, which the legacy deploy path now passes.
