# Derive RMN Remote addresses from ramp contracts' on-chain static config; drop rmn config keys

## Executive Summary

- Source and destination readers now read the chain's RMN Remote address from the OnRamp/OffRamp
  static config (one bounded RPC call at construction) instead of a separately configured address
  that could drift from, or be mistyped against, what the ramps actually enforce.
- The `rmn_remote_addresses` (verifier/token-verifier app config) and `rmn_address` (executor
  chain config) fields are removed entirely — no back-compat. App config decoding is strict, so
  job specs still carrying these keys fail to load; regenerate and re-propose specs with the
  current deployment changesets, which no longer write them.
- The CL-mode entry points (`NewVerificationCoordinator`, `NewExecutorCoordinator`) keep their
  signatures — the derivation happens inside the readers with a bounded context.
- Both constructors now fail at startup if the derivation read fails or the ramp reports a zero
  RMN Remote, and log the derived address per chain.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `NewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:46` | [Reader constructor changes](#reader-constructor-changes) |
| `destinationreader.NewEvmDestinationReader` | signature-changed | `NewEvmDestinationReader\(` | `integration/pkg/destinationreader/evm_destination_reader.go:73` | [Reader constructor changes](#reader-constructor-changes) |
| `destinationreader.Params.RmnRemoteAddress` | removed | `RmnRemoteAddress` | `integration/pkg/destinationreader/evm_destination_reader.go` | [Reader constructor changes](#reader-constructor-changes) |
| `chainaccess.CommitteeConfig.RMNRemoteAddresses` | removed | `rmn_remote_addresses` | `pkg/chainaccess/registry.go` | [Config fields removed](#config-fields-removed) |
| `chainaccess.DestinationChainConfig.RmnAddress` | removed | `rmn_address` | `pkg/chainaccess/registry.go` | [Config fields removed](#config-fields-removed) |
| `adapters.VerifierContractAddresses.RMNRemoteAddress` / `adapters.TokenVerifierChainAddresses.RMNRemoteAddress` | removed | `RMNRemoteAddress` | `deployment/adapters/` | [Config fields removed](#config-fields-removed) |
| `commit.Config.Validate` | behavior-changed | `func \(c \*Config\) Validate` | `verifier/pkg/commit/config.go:305` | [Validation](#validation) |
| `executor.Configuration.Validate` | behavior-changed | `func \(c \*Configuration\) Validate` | `executor/config.go:98` | [Validation](#validation) |
| `evm.deriveRMNRemoteFromOnRamp` / `destinationreader.deriveRMNRemoteFromOffRamp` | added | `deriveRMNRemote` | `integration/pkg/accessors/evm/evm_source_reader.go:136` | [Derivation](#derivation) |

## Breaking Changes

### Reader constructor changes

- **What:** `NewEVMSourceReader` gains a leading `ctx context.Context` and loses the
  `rmnRemoteAddress common.Address` parameter. `NewEvmDestinationReader` gains a leading `ctx`;
  `Params.RmnRemoteAddress` is removed.
- **Before:** both constructors bound the RMN Remote contract at a caller-supplied address.
- **After:** each binds the ramp contract (OnRamp / OffRamp respectively), reads
  `GetStaticConfig().RmnRemote` with a 10-second bounded context, and binds RMN Remote at the
  derived address.
- **Why:** the on-chain value is the address the ramp itself enforces; a configured copy can drift
  or be mistyped, which would silently curse-check the wrong contract.
- **Who:** both functions have call sites only inside this repo (the EVM accessor factory and the
  two CL constructors), all updated here. The CL entry points consumed by the Chainlink node repo
  (`NewVerificationCoordinator`, `NewExecutorCoordinator`) are unchanged and pass a bounded
  background context internally.

### Config fields removed

- **What:** `chainaccess.CommitteeConfig.RMNRemoteAddresses` and
  `chainaccess.DestinationChainConfig.RmnAddress` are deleted, along with the deployment adapter
  fields `adapters.VerifierContractAddresses.RMNRemoteAddress` and
  `adapters.TokenVerifierChainAddresses.RMNRemoteAddress` and all changeset/datastore plumbing
  that resolved the RMN proxy and wrote these fields into generated specs.
- **Before:** verifiers configured `rmn_remote_addresses` per source chain and executors
  configured `rmn_address` per destination chain; both were validated at startup.
- **After:** neither key exists. App config decoding rejects unknown keys
  (`bootstrap.GetAppConfig` fails on undecoded TOML), so any job spec still carrying
  `rmn_remote_addresses` or `rmn_address` fails to load. Specs must be regenerated with the
  current changesets and re-proposed — there is no backward compatibility for old specs.
- **Why:** the on-chain ramp static config is the address the ramp itself enforces; a configured
  copy can drift or be mistyped, which would silently curse-check the wrong contract. Removing the
  knobs outright (rather than deprecating them) eliminates the footgun.

## Behavior Changes

### Derivation

The RMN Remote address is constructor-set in both ramp contracts and immutable, so it is read once
at reader construction. A failed read or a zero address fails construction — the job retries at
start rather than running with a wrong or missing RMN binding. The derived address is logged per
chain (`Derived RMN Remote address from OnRamp/OffRamp static config`). The standalone accessor
factory's source-reader gate is on-ramp-only and its destination gate off-ramp-only; with the
`rmn_address` field gone, a destination config entry without an off-ramp address is simply not a
destination configuration.

### Validation

`commit.Config.Validate` no longer requires an RMN map matching the onramp keys, and
`executor.Configuration.Validate` no longer requires `rmn_address` — neither field exists. Config
correctness for RMN now reduces to "the ramps are configured correctly on-chain," which the
derivation read enforces at startup.

## Migration Guide

1. Downstream code constructing readers: pass a context and drop the RMN address argument/field.
2. External chain-family implementations of the verifier/token-verifier config adapter interfaces:
   drop `RMNRemoteAddress` from the returned address structs.
3. Operators and spec authors: regenerate job specs with the current deployment changesets (they
   no longer emit `rmn_remote_addresses` / `rmn_address`) and redeploy. Specs carrying the removed
   keys are rejected at load.

## Compatibility & Requirements

- **No backward compatibility for old job specs.** Strict TOML decoding rejects the removed keys;
  a spec regeneration and redeploy is required.
- No dependency changes; the static-config getters come from the already-imported
  `onramp`/`offramp` bindings.
- Construction-time behavior changes: one additional RPC call per reader at startup, and accessor
  construction now fails if the ramp's static config cannot be read.
- Test/development harnesses that configure placeholder ramp addresses with nothing deployed on
  the chain must now answer `getStaticConfig` at those addresses. The devenv local-mode service
  tests install a small `anvil_setCode` stub returning a static config with a non-zero
  `rmnRemote`.
- `TestCreateAccessorFactoryDoesNotDialRPCDuringConstruction` still holds: the read happens in
  `GetAccessor`, not in factory construction.

## References

- Prior entries: `2026-08-13_cutover_parity_followups.md` (removed the dead
  `SourceConfig.RMNRemoteAddress` field), `2026-08-13_standalone_executor_observability.md`
