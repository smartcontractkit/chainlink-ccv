# Remove executorProxy from the public deployments/adapter API

## Summary

Ticket: https://smartcontract-it.atlassian.net/browse/CCIP-12088

`VerifierContractAddresses.ExecutorProxyAddress` has been renamed to
`ExecutorAddress`. "ExecutorProxy" is an EVM-only contract concept that had leaked
into the cross-family adapter API, forcing non-EVM implementations to name their
plain executor address after an abstraction they do not have.

Downstream the value is consumed only as the executor's on-ramp address
(`executorOnRampAddrs` -> `DefaultExecutorOnRampAddresses`), so the rename is a pure
naming change with no behavior difference.

---

## Breaking change: `VerifierContractAddresses.ExecutorProxyAddress` -> `ExecutorAddress`

```go
// deployment/adapters/verifier_config.go
type VerifierContractAddresses struct {
    CommitteeVerifierAddress string
    OnRampAddress            string
    ExecutorAddress          string // was: ExecutorProxyAddress
    RMNRemoteAddress         string
}
```

**Action required for altVM implementations** (`chainlink-ccip-solana`,
`chainlink-canton`, and any other family adapters): when you bump the
`chainlink-ccv/deployment` dependency, update the field set in your
`VerifierConfigAdapter.ResolveVerifierContractAddresses` return value:

```go
return &ccvadapters.VerifierContractAddresses{
    CommitteeVerifierAddress: committeeVerifierAddr,
    OnRampAddress:            onRampAddr,
    ExecutorAddress:          executorAddr, // was: ExecutorProxyAddress
    RMNRemoteAddress:         rmnRemoteAddr,
}, nil
```

The EVM implementation and its consumers in `chainlink-ccv` have already been
updated.

## Follow-up: drop the "register the executor under both values" workaround

Because the public field was named after the EVM proxy, some implementations
registered their executor a second time under an `ExecutorProxy` datastore contract
type to mirror EVM. That is no longer implied by the public API. Implementations are
free to resolve the executor from their own native contract type and remove the
duplicate `ExecutorProxy` registration. `chainlink-canton` already resolves from its
native `Executor` type; `chainlink-ccip-solana` still double-registers and can drop
it in a separate change.

Note: the EVM `sequences.ExecutorProxyType` datastore contract type is unchanged.
It is the on-chain identity of a real EVM proxy contract and is internal to the EVM
adapter, not part of the cross-family adapter API.
