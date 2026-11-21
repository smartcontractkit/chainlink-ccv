# Preserve initially disabled verifier chains

## Summary

- Standalone verifier jobs can carry per-NOP `initial_disabled_chain_selectors` for CL-to-standalone migration.
- Before source readers start, the verifier seeds missing chain-status rows for those selectors with `disabled = true` and a zero finalized height.
- Existing status rows are never overwritten, so a later explicit operator re-enable survives restarts.
- A failed status read or seed write fails job initialization rather than allowing signing with unknown migration state.
- CL-mode proposal generation rejects the field because older Chainlink node images do not support it.
- Empty configuration omits the field from generated job specs, leaving existing job bytes unchanged.

## Deployment

CLD passes the selectors through `initialDisabledChainSelectors`, keyed by NOP alias, in `apply-verifier-config` or `apply-verifier-executor-config` input. The selectors must be canonical decimal strings, unique, and assigned to that NOP in the committee.

The field is intended for initial migration only. It does not copy finalized block heights and does not replace the existing chain-status enable/disable CLI for later operations. Remove the migration input after the initial standalone job has persisted the disabled rows; subsequent ordinary job regeneration needs no seeding field.

## Verification

Unit tests cover spec generation and validation, omission for existing jobs, fail-closed database behavior, seeding without an active source reader, and preservation of existing enabled and disabled rows.
