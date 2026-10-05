# New `disable_finality_checkers` option for the token verifier

## Executive Summary

- The token verifier reads `disable_finality_checkers`. The option is a list of chain selectors.
  The verifier does not run the finality violation checker for the chains in the list.
- The committee verifier has the same option (`commit.Config.DisableFinalityCheckers`). The token
  verifier did not have it. The token verifier always ran the checker.
- A chain that does not make a block for each slot needs the option. Solana is one example. The
  checker reports `missing block header for block N` and stops the source reader. No RPC server can
  supply a block that the chain did not make.
- The option applies to the CCTP verifier and to the Lombard verifier. The source chain causes the
  problem, not the attestation service.
- The change only adds. If you do not set the key, the verifier operates as before.
- The change does not correct the checker. The checker continues to report a missed slot as a
  violation. A correction to the checker is necessary later.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `token.Config.DisableFinalityCheckers` | added | `DisableFinalityCheckers \[\]string` | `verifier/pkg/token/config.go:31` | [#disable-the-checker-for-one-chain](#disable-the-checker-for-one-chain) |
| `createSourceConfigs` | behavior-changed | `func createSourceConfigs\(` | `cmd/verifier/tokenfactory.go:341` | [#disable-the-checker-for-one-chain](#disable-the-checker-for-one-chain) |
| `createCCTPCoordinator` | behavior-changed | `func createCCTPCoordinator\(` | `cmd/verifier/tokenfactory.go:235` | [#disable-the-checker-for-one-chain](#disable-the-checker-for-one-chain) |
| `createLombardCoordinator` | behavior-changed | `func createLombardCoordinator\(` | `cmd/verifier/tokenfactory.go:286` | [#disable-the-checker-for-one-chain](#disable-the-checker-for-one-chain) |

## Breaking Changes

*No breaking changes.* If the config does not have the key, the field is `nil`.
`slices.Contains(nil, selector)` gives `false`. This is the same value that
`SourceConfig.DisableFinalityChecker` had before. A new field lets the strict decoder accept one
more key. The decoder rejects no key that it accepted before. The three changed functions are not
exported. All `token.Config` literals in this repository use field names.

## Migration Guide

Do nothing for an EVM-only deployment. Each token verifier in `chainlink-ccv-deploy` is EVM-only.

To disable the checker for a chain, do these steps:

1. Add the chain selector to the app config of the token verifier.
2. Put the key at the top level, at the same level as `on_ramp_addresses`.
3. Do not put the key in `[[token_verifiers]]`.

```toml
disable_finality_checkers = ["16423721717087811551"]

[on_ramp_addresses]
16423721717087811551 = "0x…"
```

NOTE: Install a binary with this change before you add the key. `JobSpec.GetAppConfig` rejects a key
that it cannot decode. An older binary does not start.

## Disable the checker for one chain

`createSourceConfigs` receives the list of chain selectors. The function sets
`DisableFinalityChecker: slices.Contains(disableFinalityCheckers, strSelector)`. The committee
verifier does the same at `cmd/verifier/servicefactory.go:247`. `createCCTPCoordinator` and
`createLombardCoordinator` send the list from `cfg.DisableFinalityCheckers`.

Before this change, no code sets this field, and the field keeps its zero value. The checker runs
for each source chain, and you cannot disable it.

## Compatibility & Requirements

- **Rollout:** No steps. The change adds one optional key. Existing configs continue to operate.
- **Rollback:** Remove the key from each config that has it. Then install the older binary.
- **Downstream:** `chainlink-deployments` does not have this key.
  `tokenVerifierGeneratedConfigOutput` does not write it, and `mergeTokenConfigs` removes it when it
  makes the config again. Set the key in the mounted app config until you correct these two
  functions.
