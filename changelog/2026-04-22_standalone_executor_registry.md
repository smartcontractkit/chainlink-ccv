# Use Registry in Standalone Executor

## Summary

### Standalone executor is now family agnostic.

`cmd/executor/standalone/main.go` now uses `chainaccess.NewRegistry` to build
chain accessors instead of constructing EVM readers and transmitters directly.
The chain init loop calls `accessor.DestinationReader()` and
`accessor.ContractTransmitter()`, and skips any chain where either returns an
error.

### `chainaccess.Accessor` getter signatures changed

Two new getters were added to `chainaccess.Accessor` and the existing getter was modified.
They return an error when the capability is not available for the chain, rather than returning nil:

```go
// Before
SourceReader() SourceReader

// After
SourceReader() (SourceReader, error)
DestinationReader() (DestinationReader, error)
ContractTransmitter() (ContractTransmitter, error)
```

Callers must check the error before using the returned value.

### `GetAccessor` should succeeds even when capabilities are partially unavailable

`AccessorFactory.GetAccessor` should returns a  valid `Accessor` whenever the
chain selector is recognized, even if one or more of its capabilities 
(e.g. `SourceReader` when `on_ramp_addresses` is absent) could not be constructed.
Missing capabilities are reported as errors only when the corresponding getter is called.

Previously, the GetAccessor call would fail because there was only a single capability.

