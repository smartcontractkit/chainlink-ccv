# Derive RMN Remote addresses from ramp contracts' on-chain static config; deprecate rmn config keys

## Executive Summary

- Source and destination readers now read the chain's RMN Remote address from the OnRamp/OffRamp
  static config (one bounded RPC call at construction) instead of trusting a separately configured
  address that could drift from, or be mistyped against, what the ramps actually enforce.
- The `rmn_remote_addresses` (verifier/token-verifier app config) and `rmn_address` (executor
  chain config) fields are DEPRECATED but still accepted: old and new job specs both load, so the
  node rollout and the config rollout do not need to be coordinated. When a configured value
  disagrees with the on-chain derived address, the reader logs a warning and uses the derived
  address. Remove the fields once all deployed specs no longer carry them.
- The deployment tooling resolves the RMN proxy best-effort and still emits the deprecated keys
  when the datastore has a record for the chain, so regenerated specs keep working for node
  binaries that predate this change; chains without an RMN proxy record get no entry.
- The CL-mode entry points (`NewVerificationCoordinator`, `NewExecutorCoordinator`) keep their
  signatures — the derivation happens inside the readers with a bounded context.
- Both reader constructors now fail at startup if the derivation read fails or the ramp reports a
  zero RMN Remote, and log the derived address per chain.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `NewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:46` | [Reader constructor changes](#reader-constructor-changes) |
| `destinationreader.NewEvmDestinationReader` | signature-changed | `NewEvmDestinationReader\(` | `integration/pkg/destinationreader/evm_destination_reader.go:78` | [Reader constructor changes](#reader-constructor-changes) |
| `commit.Config.Validate` | behavior-changed | `func \(c \*Config\) Validate` | `verifier/pkg/commit/config.go:317` | [Validation](#validation) |
| `executor.Configuration.Validate` | behavior-changed | `func \(c \*Configuration\) Validate` | `executor/config.go:105` | [Validation](#validation) |
| `chainaccess.CommitteeConfig.RMNRemoteAddresses` | deprecated | `rmn_remote_addresses` | `pkg/chainaccess/registry.go` | [Config fields deprecated](#config-fields-deprecated) |
| `chainaccess.DestinationChainConfig.RmnAddress` | deprecated | `rmn_address` | `pkg/chainaccess/registry.go` | [Config fields deprecated](#config-fields-deprecated) |
| `adapters.VerifierContractAddresses.RMNRemoteAddress` / `adapters.TokenVerifierChainAddresses.RMNRemoteAddress` | deprecated | `RMNRemoteAddress` | `deployment/adapters/` | [Config fields deprecated](#config-fields-deprecated) |
| `destinationreader.Params.RmnRemoteAddress` | deprecated | `RmnRemoteAddress` | `integration/pkg/destinationreader/evm_destination_reader.go` | [Reader constructor changes](#reader-constructor-changes) |
| `evm.deriveRMNRemoteFromOnRamp` / `destinationreader.deriveRMNRemoteFromOffRamp` | added | `deriveRMNRemote` | `integration/pkg/accessors/evm/evm_source_reader.go:148` | [Derivation](#derivation) |

## Breaking Changes

### Reader constructor changes

- **What:** `NewEVMSourceReader` gains a leading `ctx context.Context`, and its
  `rmnRemoteAddress common.Address` parameter becomes the deprecated, optional
  `configuredRMNRemoteAddress` (pass the zero address when unconfigured). `NewEvmDestinationReader`
  gains a leading `ctx`; `Params.RmnRemoteAddress` becomes deprecated and optional (empty when
  unconfigured).
- **Before:** both constructors bound the RMN Remote contract at a caller-supplied address.
- **After:** each binds the ramp contract (OnRamp / OffRamp respectively), reads
  `GetStaticConfig().RmnRemote` with a 10-second bounded context, and binds RMN Remote at the
  derived address. A non-zero/non-empty configured value that disagrees with the derived address
  produces a warning log; the derived address always wins.
- **Why:** the on-chain value is the address the ramp itself enforces; a configured copy can drift
  or be mistyped, which would silently curse-check the wrong contract.
- **Who:** both functions have call sites only inside this repo (the EVM accessor factory and the
  two CL constructors), all updated here. The CL entry points consumed by the Chainlink node repo
  (`NewVerificationCoordinator`, `NewExecutorCoordinator`) are unchanged and pass a bounded
  background context internally.

## Behavior Changes

### Derivation

The RMN Remote address is constructor-set in both ramp contracts and immutable, so it is read once
at reader construction. A failed read or a zero address fails construction — the job retries at
start rather than running with a wrong or missing RMN binding. The derived address is logged per
chain (`Derived RMN Remote address from OnRamp/OffRamp static config`). The standalone accessor
factory's source-reader gate is on-ramp-only and its destination gate off-ramp-only; a destination
config entry carrying only the deprecated `rmn_address` still fails the destination gate with a
"requires a valid non-zero off-ramp address" error rather than being silently ignored.

### Config fields deprecated

`chainaccess.CommitteeConfig.RMNRemoteAddresses` and `chainaccess.DestinationChainConfig.RmnAddress`
remain in the config schema as deprecated, optional fields, so job specs written before this change
still decode (app config decoding is strict — unknown keys fail) and there is no cutover window in
which a fleet running mixed binaries cannot share one spec:

- Old binary + old spec: unchanged (fields required and used).
- New binary + old spec: fields decode; the readers derive the authoritative address on-chain and
  warn if a configured value disagrees.
- New binary + new spec (fields absent): derives on-chain, no warning.
- Old binary + new spec: fails validation (fields required there) — so keep emitting the keys via
  the deployment tooling until the fleet is fully upgraded.

The deployment changesets (`apply_verifier_config`, `apply_executor_config`,
`generate_token_verifier_config`) resolve the RMN proxy from the datastore best-effort: present
records are still resolved and emitted into the deprecated keys (duplicate records remain an
error), absent records yield no entry rather than a failure. Token-verifier configs already stored
with `rmn_remote_addresses` keep those entries across `MergeTokenVerifierConfig` merges.

### Validation

`commit.Config.Validate` no longer requires an RMN map matching the onramp keys, and
`executor.Configuration.Validate` no longer requires `rmn_address` — both fields are optional.
Config correctness for RMN now reduces to "the ramps are configured correctly on-chain," which the
derivation read enforces at startup.

## Migration Guide

1. Downstream code constructing readers: pass a context as the first argument. The RMN address
   argument/field is now optional — pass the zero address / empty string, or keep passing the
   configured value during the transition to get mismatch warnings.
2. External chain-family implementations of the verifier/token-verifier config adapter interfaces:
   keep returning `RMNRemoteAddress` when the deployment has an RMN proxy record (it feeds the
   deprecated spec keys); return empty when it does not — absence is no longer an error.
3. Operators: no spec regeneration required. Specs carrying `rmn_remote_addresses` / `rmn_address`
   keep loading; drop the keys from future specs once every node in the fleet runs a binary with
   on-chain derivation.

## Deprecations

- **`chainaccess.CommitteeConfig.RMNRemoteAddresses` (`rmn_remote_addresses`)** — deprecated in
  favor of on-chain derivation from each OnRamp's static config. Planned removal: once all
  deployed specs no longer carry the key.
- **`chainaccess.DestinationChainConfig.RmnAddress` (`rmn_address`)** — deprecated in favor of
  on-chain derivation from each OffRamp's static config. Planned removal: same condition.
- **`destinationreader.Params.RmnRemoteAddress` / `NewEVMSourceReader`'s
  `configuredRMNRemoteAddress`** — same deprecation, at the constructor-argument level.
- **`adapters.VerifierContractAddresses.RMNRemoteAddress` /
  `adapters.TokenVerifierChainAddresses.RMNRemoteAddress`** — same deprecation, at the deployment
  tooling level.

## Compatibility & Requirements

- **Backward compatible with old job specs.** Strict TOML decoding still accepts the deprecated
  keys; no spec regeneration or coordinated rollout is required.
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
