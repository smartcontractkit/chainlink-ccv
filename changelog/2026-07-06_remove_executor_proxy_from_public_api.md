# Remove executorProxy from the public deployments/adapter API

## Summary

Ticket: https://smartcontract-it.atlassian.net/browse/CCIP-12088

The executor address used to be resolved twice, by two different adapter methods, and
one of them exposed an EVM-only "ExecutorProxy" concept in the cross-family API:

- `VerifierConfigAdapter.ResolveVerifierContractAddresses` returned it as
  `VerifierContractAddresses.ExecutorProxyAddress`.
- `ExecutorConfigAdapter.BuildChainConfig` returned it as
  `executor.ChainConfiguration.DefaultExecutorAddress`.

Because the verifier struct field was named after the EVM proxy, non-EVM implementations
mirrored EVM by registering their executor under a second `ExecutorProxy` datastore
contract type so both adapters could resolve it.

This change consolidates executor resolution into a single method on the executor adapter
and removes the executor entirely from the verifier adapter's public struct.

---

## Breaking change: executor removed from `VerifierContractAddresses`

`ExecutorProxyAddress` is gone from the struct (it is not renamed):

```go
// deployment/adapters/verifier_config.go
type VerifierContractAddresses struct {
    CommitteeVerifierAddress string
    OnRampAddress            string
    RMNRemoteAddress         string
    // ExecutorProxyAddress removed
}
```

## Breaking change: new `ResolveExecutorAddress` on `ExecutorConfigAdapter`

The executor address now has a single source of truth on the executor adapter:

```go
// deployment/adapters/executor_config.go
type ExecutorConfigAdapter interface {
    GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64
    ResolveExecutorAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) // new
    BuildChainConfig(ds datastore.DataStore, chainSelector uint64, qualifier string) (executor.ChainConfiguration, error)
}
```

The `ApplyVerifierConfig` / `AddNOPToCommittee` changesets now obtain the executor
on-ramp address by calling `ResolveExecutorAddress` through the executor registry, rather
than reading it from the verifier struct. `BuildChainConfig` should resolve its
`DefaultExecutorAddress` via `ResolveExecutorAddress` so the address is resolved in exactly
one place per family.

**Action required for altVM implementations** (`chainlink-ccip-solana`,
`chainlink-canton`, and any other family adapters), when you bump the
`chainlink-ccv/deployment` dependency:

1. Drop the executor field from your `VerifierConfigAdapter.ResolveVerifierContractAddresses`
   return value:

   ```go
   return &ccvadapters.VerifierContractAddresses{
       CommitteeVerifierAddress: committeeVerifierAddr,
       OnRampAddress:            onRampAddr,
       RMNRemoteAddress:         rmnRemoteAddr,
       // ExecutorProxyAddress: ... — remove
   }, nil
   ```

2. Implement `ResolveExecutorAddress` on your `ExecutorConfigAdapter`, resolving from your
   family's native executor contract type:

   ```go
   func (a *MyExecutorConfigAdapter) ResolveExecutorAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
       return dsutils.FindAndFormatRef(ds, datastore.AddressRef{
           Type:      datastore.ContractType(executor.ContractType), // native type, not "ExecutorProxy"
           Qualifier: qualifier,
           Version:   executor.Version,
       }, chainSelector, toAddress)
   }
   ```

3. You can now drop the "register the executor under both values" workaround. Once your
   `ResolveExecutorAddress` (and `BuildChainConfig`, `GetDeployedChains`) read the native
   executor type, the duplicate `ExecutorProxy` `AddressRef` registrations are no longer
   needed. For `chainlink-ccip-solana` this means removing the second registration in
   `deploy_chain_contracts.go` and `devenv/deployment.go`, pointing
   `executor_config_adapter.go`, `messaging.go`, and `sequences/adapter.go` at the native
   `Executor` type, and deleting the `ProxyContractType` constant. `chainlink-canton`
   already resolves from its native `Executor` type, so it only needs steps 1 and 2.

The EVM implementation keeps its real proxy contract: `EVMCCVExecutorConfigAdapter`
resolves `sequences.ExecutorProxyType` internally. That datastore contract type is the
on-chain identity of a genuine EVM proxy contract and is internal to the EVM adapter — it
is not part of the cross-family adapter API.

## Behavior note: verifier path now requires an executor adapter

`ApplyVerifierConfig` / `AddNOPToCommittee` now resolve the executor through the executor
registry, so an `ExecutorConfigAdapter` must be registered for every committee chain family
(previously the verifier adapter resolved the executor itself). Every family already
registers both adapters together, so this is a no-op in practice, but a family that
registered only a verifier adapter will now error with "no executor config adapter
registered for chain N".
