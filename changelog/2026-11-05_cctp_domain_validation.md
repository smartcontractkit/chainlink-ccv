# CCTP verifier fails at startup for chains with no domain

## Executive Summary

- `cctp.NewAttestationService` now fails if a configured chain has no CCTP domain, from either `cctp_domain_mapping` or the chain's built-in `CCTPCodec` table.
- Previously such a chain loaded fine and every message from it failed at fetch time with `unsupported source chain selector`; the misconfiguration is now caught when the service is built.
- Affects the CCTP token verifier (`verifier/pkg/token/cctp`) and every caller of `NewAttestationService`, including `cmd/verifier/tokenfactory.go`.
- `validate-config` (and the bootstrap check before a job replaces a running one) now also rejects an EVM `verifier_addresses` chain with no domain, offline, without starting the service.
- Each chain family supplies its own built-in domain table by registering it from a package the token verifier binary imports; the shared token verifier code names no family.
- Breaking only for configs that list a chain with no domain anywhere; configs whose chains all have a domain are unaffected.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.NewAttestationService` | behavior-changed | `NewAttestationService\(` | `verifier/pkg/token/cctp/attestation.go:73` | [#domain-validation](#domain-validation) |
| `tokenVerifierFactory.Validate` | behavior-changed | `tokenVerifierFactory\) Validate\(` | `cmd/verifier/tokenfactory.go:66` | [#offline-domain-validation](#offline-domain-validation) |
| `cctp.ValidateDomains` | added | `\bValidateDomains\(` | `verifier/pkg/token/cctp/attestation.go:115` | [#domain-validation](#domain-validation) |
| `cctp.resolveDomain` | added | `\bresolveDomain\(` | `verifier/pkg/token/cctp/attestation.go:99` | [#domain-resolution](#domain-resolution) |
| `cctp.BaseDomainTable` | added | `\bBaseDomainTable\b` | `verifier/pkg/token/cctp/base_domains.go:13` | [#offline-domain-validation](#offline-domain-validation) |
| `cctp.RegisterBaseDomainTable` | added | `\bRegisterBaseDomainTable\(` | `verifier/pkg/token/cctp/base_domains.go:22` | [#offline-domain-validation](#offline-domain-validation) |
| `cctp.BaseDomainTableFor` | added | `\bBaseDomainTableFor\(` | `verifier/pkg/token/cctp/base_domains.go:33` | [#offline-domain-validation](#offline-domain-validation) |
| `validateCCTPDomains` | added | `\bvalidateCCTPDomains\(` | `cmd/verifier/tokendomains.go:27` | [#offline-domain-validation](#offline-domain-validation) |
| `evm/cctpdomains` | added | `accessors/evm/cctpdomains` | `integration/pkg/accessors/evm/cctpdomains/cctpdomains.go` | [#offline-domain-validation](#offline-domain-validation) |

## Breaking Changes

### CCTP config with a chain that has no domain is rejected

- **What changed:** `NewAttestationService` validates the chains in `verifier_addresses` and `verifier_resolver_addresses` against the available domains.
- **Before:** construction succeeded; fetches for the affected chain failed per message with `unsupported source chain selector: <selector>`.
- **After:** construction fails with `no CCTP domain for chain selectors [<selectors>]: add them to cctp_domain_mapping`. All missing selectors are listed, sorted.
- **Why:** surface the misconfiguration at startup instead of as a stream of per-message errors.
- **Who is affected:** operators whose CCTP job spec lists a chain that is neither in `cctp_domain_mapping` nor in the chain family's built-in table, and out-of-tree callers of `NewAttestationService`.

### `validate-config` rejects an EVM chain with no domain

- **What changed:** `tokenVerifierFactory.Validate` runs `validateCCTPDomains` after the normal config validation. It is used by `validate-config` and by the bootstrap lifecycle before a job replaces a running one.
- **Before:** such a config passed `validate-config`; the service started and the affected verifier was skipped (shown as degraded on `/health`).
- **After:** `validate-config` exits 1 with `invalid cctp verifier "<id>": no CCTP domain for chain selectors [<selectors>]: add them to cctp_domain_mapping`. A running job is kept when its replacement is rejected.
- **Also rejected:** a `verifier_addresses` chain selector that is not a known chain selector, with `invalid CCTP verifier chain selector`.
- **Scope:** EVM only for now. Chains of a family with no registered table are not checked offline (see [#offline-domain-validation](#offline-domain-validation)).
- **Who is affected:** operators whose deployed spec already lists an EVM chain with no domain; the next redeploy of it is rejected instead of starting degraded.

## Migration Guide

1. If startup fails with `no CCTP domain for chain selectors [...]`, add each listed selector to `cctp_domain_mapping` with its Circle domain, or remove the chain from `verifier_addresses` / `verifier_resolver_addresses` if it should not be served.
2. Out-of-tree callers: pass a `CCTPCodec` for every `verifier_addresses` chain. If that codec has no built-in domain for the chain, also add an entry in `ParsedCCTPDomainOverrides`.

```toml
[token_verifiers.cctp_domain_mapping]
"5009297550715157269" = 0
```

3. CI: run `validate-config --config <bootstrap.toml>` against each token verifier config. It now fails on an EVM chain with no domain, with the same fix as step 1.
4. Chain families other than EVM: to have `validate-config` check your chains, expose a static domain lookup and register it from a package that only the token verifier binary imports.

```go
// package cctpdomains: blank-imported by the token verifier's main.go
func init() {
	cctp.RegisterBaseDomainTable(chainsel.FamilyXXX, func(sel protocol.ChainSelector) (uint32, bool) {
		return xxx.CCTPDomain(uint64(sel))
	})
}
```

## Domain validation

- Every `verifier_addresses` chain must have a domain.
- A `verifier_resolver_addresses` chain is checked only if it has a codec in the `cctpCodecs` argument. Resolver-only chains (destinations) have no codec and are not checked.
- The check is in-memory (no I/O), so it is safe in a constructor under the repo's no-eager-I/O rule.

## Offline domain validation

- `validate-config` has no chain accessors, so it cannot use the `CCTPCodec` that startup uses. Each family registers its built-in table instead, with `cctp.RegisterBaseDomainTable(family, table)`.
- `validateCCTPDomains` resolves each `verifier_addresses` chain's family with `chainsel.GetSelectorFamily`, takes that family's table, and calls the same `cctp.ValidateDomains` as startup. `cctp_domain_mapping` still takes precedence over the table.
- EVM registers `evm.CCTPDomain` from the new package `integration/pkg/accessors/evm/cctpdomains`, which only `cmd/verifier/token/main.go` imports. The committee verifier and executor do not.
- Checked: `verifier_addresses` chains of a family with a registered table. Skipped: chains of other families, and resolver-only chains, whose codecs exist only at startup.
- `Start` is unchanged: `NewAttestationService` still runs `ValidateDomains` with the live codecs, and on failure skips only that verifier and reports `degraded` on `/health`. The offline check can only reject configs startup would also flag.
- The check is a static map lookup (no I/O).

## Domain resolution

`resolveDomain(overrides, codec, selector)` returns the `cctp_domain_mapping` entry if present, else `codec.Domain(selector)`, else not found. `Fetch` now uses the same helper, so validation and fetch cannot disagree. Behavior of `Fetch` is unchanged.

## Compatibility & Requirements

- **Rollout:** check job specs for CCTP chains that lack a built-in domain before deploying; add `cctp_domain_mapping` entries first. Run `validate-config` on them to find any.
- **Rollback:** a binary swap; the previous binary does not validate domains.
- **Import requirement:** a token verifier binary must blank-import `evm/cctpdomains` (as `cmd/verifier/token` does) for `validate-config` to check EVM chains. Without it EVM chains are skipped silently and only startup catches the gap.
- **Registry:** `RegisterBaseDomainTable` panics on a duplicate family registration, like the other chainaccess registries.
- **API:** `cctp.validateDomains` is now exported as `cctp.ValidateDomains`. `NewTokenVerifierServiceFactory` keeps its signature.

## References

- Prior changelog entries this builds on: `2026-11-03_cctp_domain_mapping.md`
- Docs: `verifier/docs/token_verifier.md` (`cctp_domain_mapping` row)
- Similar per-family registry: `chainaccess.RegisterDeclaredChainCoverageChecker` (`pkg/chainaccess/coverage.go`)
