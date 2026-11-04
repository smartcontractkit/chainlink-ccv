# Configurable CCTP domain mapping

## Executive Summary

- Adds an optional `cctp_domain_mapping` table to a CCTP `[[token_verifiers]]` entry: source chain selector → Circle CCTP domain.
- Lets operators support a chain Circle has added without waiting for a release that extends the built-in domain tables (e.g. `integration/pkg/accessors/evm/cctp_domains.go`).
- Affects the CCTP token verifier config (`cctp.CCTPConfig`), `cctp.AttestationService`, and adds `common.ParseChainDomainMap`.
- No breaking changes: the key is optional, and without it the built-in catalog is used exactly as before.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.CCTPConfig.CCTPDomainOverrides` | added | `\bCCTPDomainOverrides\b` | `verifier/pkg/token/cctp/config.go:50` | [#cctp_domain_mapping-config-key](#cctp_domain_mapping-config-key) |
| `cctp.CCTPConfig.ParsedCCTPDomainOverrides` | added | `\bParsedCCTPDomainOverrides\b` | `verifier/pkg/token/cctp/config.go:51` | [#cctp_domain_mapping-config-key](#cctp_domain_mapping-config-key) |
| `cctp.ConfigKeys` (`cctp_domain_mapping`) | added | `cctp_domain_mapping` | `verifier/pkg/token/cctp/config.go:76` | [#cctp_domain_mapping-config-key](#cctp_domain_mapping-config-key) |
| `cctp.AttestationService.Fetch` | behavior-changed | `\.Fetch\(` | `verifier/pkg/token/cctp/attestation.go:107` | [#domain-resolution-order](#domain-resolution-order) |
| `common.ParseChainDomainMap` | added | `\bParseChainDomainMap\(` | `common/toml.go:150` | [#commonparsechaindomainmap](#commonparsechaindomainmap) |

## Breaking Changes

*No breaking changes.* Configs without `cctp_domain_mapping` parse to empty (non-nil) `ParsedCCTPDomainOverrides` and resolve domains exactly as before.

## cctp_domain_mapping config key

- **What changed:** `cctp_domain_mapping` is accepted on a `type = "cctp"`, `version = "2.0"` entry. Keys are decimal chain selectors; values are integer domains. `TryParsing` rejects the entry with `invalid cctp_domain_mapping: …` for a non-table value, a non-numeric selector, or a domain that is negative, fractional, non-numeric or larger than `uint32`.
- **Why:** previously a new Circle domain required a code change and release.
- **Who is affected:** operators writing verifier job specs; code constructing `cctp.CCTPConfig` directly.
- `CCTPDomainOverrides` (`map[string]any`) is the raw table, kept for TOML/JSON marshaling because TOML table keys must be strings. `ParsedCCTPDomainOverrides` (`map[protocol.ChainSelector]uint32`) is the typed form the service reads; it is `toml:"-"`/`json:"-"`.

```toml
[token_verifiers.cctp_domain_mapping]
"5009297550715157269" = 0
```

## Domain resolution order

`AttestationService.Fetch` resolves the source domain from `ParsedCCTPDomainOverrides[sourceChain]` first, then falls back to the chain's `CCTPCodec.Domain`. If neither has an entry it fails with `unsupported source chain selector: <selector>` and makes no Circle API request.

## common.ParseChainDomainMap

`ParseChainDomainMap(val any) (map[protocol.ChainSelector]uint32, map[string]any, error)` parses the table and returns the raw map alongside. A nil value yields an empty typed map and a nil raw map. Accepts `int`, `int64`, `uint32`, `uint64` and whole-number `float64` values (TOML decodes integers as `int64`, JSON as `float64`).

## Compatibility & Requirements

- **Rollout:** none required; the key is optional and existing specs are unaffected.
- **Rollback:** a binary swap. An older binary rejects a spec carrying `cctp_domain_mapping` as an unknown key (`unknown keys for cctp verifier`), so remove the table from specs first.

## References

- Docs: `verifier/docs/token_verifier.md` (`cctp_domain_mapping` row and example snippet)
