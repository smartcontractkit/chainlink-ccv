# CCTP verifier fails at startup for chains with no domain

## Executive Summary

- `cctp.NewAttestationService` now fails if a configured chain has no CCTP domain, from either `cctp_domain_mapping` or the chain's built-in `CCTPCodec` table.
- Previously such a chain loaded fine and every message from it failed at fetch time with `unsupported source chain selector`; the misconfiguration is now caught when the service is built.
- Affects the CCTP token verifier (`verifier/pkg/token/cctp`) and every caller of `NewAttestationService`, including `cmd/verifier/tokenfactory.go`.
- Breaking only for configs that list a chain with no domain anywhere; configs whose chains all have a domain are unaffected.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.NewAttestationService` | behavior-changed | `NewAttestationService\(` | `verifier/pkg/token/cctp/attestation.go:73` | [#domain-validation](#domain-validation) |
| `cctp.validateDomains` | added | `\bvalidateDomains\(` | `verifier/pkg/token/cctp/attestation.go:115` | [#domain-validation](#domain-validation) |
| `cctp.resolveDomain` | added | `\bresolveDomain\(` | `verifier/pkg/token/cctp/attestation.go:99` | [#domain-resolution](#domain-resolution) |

## Breaking Changes

### CCTP config with a chain that has no domain is rejected

- **What changed:** `NewAttestationService` validates the chains in `verifier_addresses` and `verifier_resolver_addresses` against the available domains.
- **Before:** construction succeeded; fetches for the affected chain failed per message with `unsupported source chain selector: <selector>`.
- **After:** construction fails with `no CCTP domain for chain selectors [<selectors>]: add them to cctp_domain_mapping`. All missing selectors are listed, sorted.
- **Why:** surface the misconfiguration at startup instead of as a stream of per-message errors.
- **Who is affected:** operators whose CCTP job spec lists a chain that is neither in `cctp_domain_mapping` nor in the chain family's built-in table, and out-of-tree callers of `NewAttestationService`.

## Migration Guide

1. If startup fails with `no CCTP domain for chain selectors [...]`, add each listed selector to `cctp_domain_mapping` with its Circle domain, or remove the chain from `verifier_addresses` / `verifier_resolver_addresses` if it should not be served.
2. Out-of-tree callers: pass a `CCTPCodec` for every `verifier_addresses` chain, or cover that chain in `ParsedCCTPDomainOverrides`.

```toml
[token_verifiers.cctp_domain_mapping]
"5009297550715157269" = 0
```

## Domain validation

- Every `verifier_addresses` chain must have a domain.
- A `verifier_resolver_addresses` chain is checked only if it has a codec in the `cctpCodecs` argument. Resolver-only chains (destinations) have no codec and are not checked.
- The check is in-memory (no I/O), so it is safe in a constructor under the repo's no-eager-I/O rule.

## Domain resolution

`resolveDomain(overrides, codec, selector)` returns the `cctp_domain_mapping` entry if present, else `codec.Domain(selector)`, else not found. `Fetch` now uses the same helper, so validation and fetch cannot disagree. Behavior of `Fetch` is unchanged.

## Compatibility & Requirements

- **Rollout:** check job specs for CCTP chains that lack a built-in domain before deploying; add `cctp_domain_mapping` entries first.
- **Rollback:** a binary swap; the previous binary does not validate domains.

## References

- Prior changelog entries this builds on: `2026-11-03_cctp_domain_mapping.md`
- Docs: `verifier/docs/token_verifier.md` (`cctp_domain_mapping` row)
