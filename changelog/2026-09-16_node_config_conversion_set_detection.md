# Node-config conversion names every set-but-dropped setting, and the ignored top-level sections

## Executive Summary

- The node-config conversion's set-detection now reads the mounted file's raw keys instead of the
  decoded chainlink-evm struct. What carries over is unchanged; only the warnings grow.
- The set-but-dropped warnings now also name settings the pinned chainlink-evm has no field for:
  options a newer node version added, and typos of real ones (`FinalityDepht = 22` silently
  reverting to the chain default was the motivating case). Non-pointer scalar leaves are covered
  too — the raw file has no set-vs-unset ambiguity.
- Per-node detection is no longer a fixed two-item list (`HTTPURLExtraWrite`, `IsLoadBalancedRPC`).
  Any set node-level key beyond Name, HTTPURL, WSURL, Order and SendOnly warns.
- New `Conversion.IgnoredSections` names the top-level sections outside `[[EVM]]` (`Log`,
  `WebServer`, `P2P`, …). The startup log prints them once; `ccv migrate inspect-config` prints
  them as `ignored_top_level_sections`, including under `--chain-selector` (file-level, so the
  list does not narrow).

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `Conversion.IgnoredSections` | added | `IgnoredSections \[\]string` | `integration/pkg/accessors/evmconfig/clnode_config.go:43` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `setChainSettingPaths` | removed | — | replaced by `droppedChainSettingPaths` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `droppedChainSettingPaths` | added | `func droppedChainSettingPaths\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:302` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `droppedNodeSettingPaths` | added | `func droppedNodeSettingPaths\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:322` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `convertNodes` | signature-changed | `func convertNodes\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:344` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `CreateEVMAccessorFactory` | behavior-changed | `IgnoredSections` | `integration/pkg/accessors/evm/factory_constructor.go:63` | [#migration-guide](#migration-guide) |
| `configReport.IgnoredSections` | added | `ignored_top_level_sections` | `cli/migrate/inspect_config.go:53` | [#migration-guide](#migration-guide) |

## Breaking Changes

*No breaking changes.* `Conversion` gains a field; both consumers (`CreateEVMAccessorFactory`,
`buildConfigReport`) are in this repository. `convertNodes` is unexported with one caller. Warning
strings for settings that warned before are unchanged, and a config that sets nothing beyond the
carried-over keys still warns on nothing.

## Migration Guide

No steps. Note for the next pre-cutover review: the `inspect-config` diff and the startup log may
name settings earlier runs did not show — options the tool's chainlink-evm version predates, typos,
and the ignored top-level sections. Each named setting was already being dropped; the change only
makes the drop visible.

## Why the detection reads the file

The typed walk had three blind spots: a setting the pinned chainlink-evm version has no field for
(the TOML decoder ignores unknown keys), a non-pointer scalar leaf (set looks like unset), and any
node field beyond the fixed two-item list. Reading the file's own keys closes all three at once and
cannot drift from what the operator wrote. The typed decode stays authoritative for the conversion
itself; the raw pass only produces warnings, and a raw failure degrades warnings rather than
failing a loadable config.

Covered by `TestConvertChainlinkNodeConfigWarnsAboutSettingsUnknownToTheTypedConfig`,
`TestConvertChainlinkNodeConfigNamesIgnoredTopLevelSections`,
`TestConvertChainlinkNodeConfigWarnsAboutSettingsFromMergedBlocks`, and the
`ignored top-level sections` subtest of `TestBuildConfigReport`.
