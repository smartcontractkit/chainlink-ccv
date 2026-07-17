# Remove `blockchain_infos` from job and application config

## Summary

`blockchain_infos` has been removed from supported CCV job/application config. A stale table is
ignored with a warning so it cannot prevent an application from starting. Chain selectors now
come from application-owned typed maps, while RPC endpoints and chain-family tuning come from
operator-local config in standalone mode or Chainlink node config in CL mode.

This is a breaking source change. Config producers must remove the table, although consumers
tolerate stale copies during rollout and do not use their contents.

## Removed APIs

| Removed API | Replacement |
|---|---|
| `bootstrap.JobSpec.GetGenericConfig` | `JobSpec.GetAppConfig` with the application's typed config |
| `chainaccess.GenericConfig.ChainConfig` | Chain-family local or node config |
| `chainaccess.GenericConfig.GetConcreteConfig` | Decode the chain-family local config directly |
| `chainaccess.GenericConfig.GetAllConcreteConfig` | Decode the chain-family local config directly |
| `executor.ConfigWithBlockchainInfo` | `executor.Configuration` |
| `executor.LoadConfigWithBlockchainInfos` | `JobSpec.GetAppConfig` followed by `Configuration.GetNormalizedConfig` |
| `token.ConfigWithBlockchainInfos` | `token.Config` |
| `services.TokenVerifierInput.GenerateConfigWithBlockchainInfos` | `TokenVerifierInput.GenerateConfig` |
| `verifier.LoadBlockchainInfo` | Enumerate selectors from the application's typed address/config maps |

`JobSpec.GetAppConfig` ignores an undecoded `blockchain_infos` section for stale-job compatibility.
Registry construction logs a warning when the section is present; no runtime configuration is
read from it.

## Runtime changes

- The token verifier enumerates source chains from `Config.OnRampAddresses`.
- The executor decodes `executor.Configuration` directly.
- Token-verifier devenv output contains application config only; its existing separate EVM config
  carries RPC connection details.

## Deployment migration

The standalone token verifier must mount an EVM config and set `EVM_CONFIG_PATH`. The final
configuration must not contain RPC URLs or a `blockchain_infos` table in
`token-verifier.toml`.

Deploy the token-verifier binary, EVM config mount, `EVM_CONFIG_PATH`, and application config
without the legacy table as one release. If a staged rollout is preferable, first mount the EVM
config while retaining the legacy table, then upgrade the binary, and finally remove the table
after all instances run the new version. The new binary warns but starts while the table is still
present; the old binary still needs it to enumerate source chains.

Persisted JD jobs no longer have to be cleaned up before the binary upgrade. Remove the empty
table from Canton jobs and re-propose them with the same `externalJobID` before or after the new
binary is deployed.

## Downstream migration

- **Solana:** remove the devenv job-config metadata shim that emits `blockchain_infos` before
  upgrading generated jobs. Solana RPC details continue to come from node/operator config.
- **Canton:** remove empty `blockchain_infos` tables from JD jobs. Canton's
  `ccip.Config.BlockchainInfos` is a separate operator-local opaque configuration surface and is
  not removed by this change.
- Historical changelogs may still describe the old format; they remain historical documentation,
  not supported configuration.
