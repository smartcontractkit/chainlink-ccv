# Remove `blockchain_infos` from job and application config

## Summary

`blockchain_infos` is no longer accepted in CCV job/application config. Chain selectors now come
from application-owned typed maps, while RPC endpoints and chain-family tuning come from
operator-local config in standalone mode or Chainlink node config in CL mode.

This is a breaking source and configuration change.

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

`JobSpec.GetAppConfig` now explicitly rejects `blockchain_infos`, even if a caller's target type
still declares a matching field.

## Runtime changes

- The token verifier enumerates source chains from `Config.OnRampAddresses`.
- The executor decodes `executor.Configuration` directly.
- Token-verifier devenv output contains application config only; its existing separate EVM config
  carries RPC connection details.

## Deployment migration

The standalone token verifier must mount an EVM config and set `EVM_CONFIG_PATH`. The final
configuration must not contain RPC URLs or a `blockchain_infos` table in
`token-verifier.toml`.

For a rolling deployment:

1. Add and mount the EVM config while retaining the legacy table. This additive revision is safe
   for the old binary.
2. Deploy the new CCV binary and remove the legacy table together. The old token-verifier binary
   still uses that table to enumerate source chains.
3. Re-propose or regenerate JD jobs without the table once every relevant binary consumes
   chain-family local/node config.

## Downstream compatibility

- **Solana:** remove the devenv job-config metadata shim that emits `blockchain_infos` before
  upgrading generated jobs. Solana RPC details continue to come from node/operator config.
- **Canton:** remove empty `blockchain_infos` tables from JD jobs. Canton's
  `ccip.Config.BlockchainInfos` is a separate operator-local opaque configuration surface and is
  not removed by this change.
- Historical changelogs may still describe the old format; they remain historical documentation,
  not supported configuration.
