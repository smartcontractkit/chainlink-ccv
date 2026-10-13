# Lombard verifier handles empty batches and attestation results

## Executive Summary

- An empty task batch returns `nil` without an attestation request.
- An unknown destination selector gives a final error. The task does not retry automatically.
- When Lombard returns duplicate APPROVED entries, the verifier uses the first entry with data.
- The token verifier does not start when two `token_verifiers` entries have the same `verifier_id`.
- The public API and wire format do not change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `lombard.Verifier.VerifyMessages` | behavior-changed | `\.VerifyMessages\(` | `verifier/pkg/token/lombard/verifier.go:88` | [Verifier results](#verifier-results) |
| `lombard.HTTPAttestationService.Fetch` | behavior-changed | `\.Fetch\(` | `verifier/pkg/token/lombard/attestation.go:191` | [Attestation selection](#attestation-selection) |
| `token.Config.Validate` | added | `\.Validate\(` | `verifier/pkg/token/config.go:38` | [Config validation](#config-validation) |

## Breaking Changes

A config with a duplicate `verifier_id` now fails at startup. The deployed configs have no duplicates.

## Verifier results

`VerifyMessages(ctx, nil)` returns `nil` before it calls `Fetch`.
For an unknown destination selector, `VerifyMessages` returns an error with `Retryable == false`.
A selector update alone does not restart that failed task.
A FAILED attestation can later become APPROVED, so it remains retriable.
Attestation decode errors also remain retriable.

## Attestation selection

`Fetch` checks entries with the same message hash in response order.
It uses the first APPROVED entry with nonempty `Data`.
If none has data, it uses the first APPROVED entry.
If none is APPROVED, it uses the first entry with the same hash.
This rule lets a Solana destination use an APPROVED entry without data.
`Fetch` checks only whether `Data` is empty.
For destinations other than Solana, the verifier decodes the selected data later.

## Config validation

`token.Config.Validate` returns an error for a duplicate `verifier_id` in `token_verifiers`.
The token verifier factory calls it right after it decodes the app config.
