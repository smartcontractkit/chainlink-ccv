# Restore standalone verifier source-reader monitoring

## Executive Summary

- Standalone committee verifiers now wrap source readers with the same observed reader used in CL mode.
- EVM source readers now receive the production critical-invariant metric callback after accessor lookup.
- Source head gauges and critical-invariant counters therefore remain available after cutover.
- CL mode, configuration schemas, and source-reader runtime behavior are unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `verifier.factory.Start` | behavior-changed | `func \(f \*factory\) Start` | `cmd/verifier/servicefactory.go:99` | [Standalone reader instrumentation](#standalone-reader-instrumentation) |
| `monitoring.FakeVerifierMetricLabeler.IncrementCriticalSourceInvariantViolations` | behavior-changed | `IncrementCriticalSourceInvariantViolations\(` | `verifier/pkg/monitoring/monitoring.go:167` | [Focused validation](#focused-validation) |
| `chainaccess.CriticalSourceInvariantCallbackSetter` | added | `CriticalSourceInvariantCallbackSetter\b` | `pkg/chainaccess/interfaces.go:58` | [Critical-invariant callback](#critical-invariant-callback) |
| `evm.SourceReader.SetCriticalSourceInvariantCallback` | added | `SetCriticalSourceInvariantCallback\(` | `integration/pkg/accessors/evm/evm_source_reader.go:112` | [Critical-invariant callback](#critical-invariant-callback) |
| `verifier.instrumentSourceReader` | added | `instrumentSourceReader\(` | `cmd/verifier/servicefactory.go:65` | [Standalone reader instrumentation](#standalone-reader-instrumentation) |

## Breaking Changes

No breaking changes.

## Behavior Changes

### Standalone reader instrumentation

The standalone committee verifier wraps every accessor-provided source reader with
`sourcereader.NewObservedSourceReader`. Calls that obtain latest, finalized, or safe heads now emit
the same source-chain gauges as CL mode. CL construction is unchanged.

### Critical-invariant callback

`chainaccess.CriticalSourceInvariantCallbackSetter` is an optional capability. The EVM source
reader implements it, allowing the standalone verifier to attach the same chain-labelled
`IncrementCriticalSourceInvariantViolations` callback that CL supplies during construction. The
callback is installed before the coordinator starts the reader; readers without the optional
capability continue to work unchanged.

### Focused validation

`TestInstrumentSourceReader` verifies that the standalone wrapper records latest and finalized head
gauges and that an attached critical-invariant callback increments the fake monitoring counter.

## Compatibility & Requirements

- No configuration or dependency changes.
- CL-mode construction and behavior are unchanged.
- The new callback interface is optional and does not expand `chainaccess.SourceReader`.

## References

- Prior changelog: `2026-08-11_cutover_parity_cleanup.md`
