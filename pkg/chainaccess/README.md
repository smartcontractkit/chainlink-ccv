# Chain Access Layer
Provides a way to inject family specific access implementations into CCIP services.

# Registry
A way to access instantiations of the chainaccess.Accessor object for a chain family.

Applications register a constructor that accepts a simple config string.

# Configuration
There are cases where accessor construction needs application-owned configuration. One
example is the on-ramp address, which is needed by both `chainaccess.SourceReader` and the
committee verifier. `GenericConfig` provides this shared application overlay.

In order to add an accessor interface, the App needs the following:
1. Add application-owned shared configuration to `pkg/chainaccess`:
```go
type MyAppSharedConfig struct {
    OnRampAddress string `toml:"on_ramp_address"`
}
```
2. Add the shared configuration to `GenericConfig`:
```go
type GenericConfig struct {
    CommitteeConfig
    MyAppSharedConfig
}
```
3. Each chain family loads connection and tuning details from operator-local config in
standalone mode, or node config in CL mode, and registers its constructor.
4. Create the registry with the typed app config so constructors receive the shared overlay:
```go
chainAccessRegistry, err := chainaccess.NewRegistry(lggr, appConfig)
accessor, err := chainAccessRegistry.GetAccessor(ctx, chainsel.ETHEREUM_MAINNET)
```

RPC endpoints and other operator-owned connection settings must not be placed in app/job config.

# Message details

Source readers supply `protocol.MessageSentEvent.MessageDetails` alongside the original decoded
`Message`. Build it from the existing event data with
`chainaccess.NewMessageDetails(message, receipts, feeToken)`. The helper normalizes addresses to
at least 32 bytes, preserves longer addresses and leading zeros, sums all receipt fees, and uses
`protocol.Finality.Requirement()` to decode finality. It performs no RPCs and uses no API types or
chain-family lookups. Missing fee data remains unavailable.

The details own their address bytes. Keep `Message` unchanged: it is the message whose ID and
signature are verified. Consumers such as policy hooks serialize the supplied details instead of
interpreting raw addresses or receipt/finality encodings. The source-reader service and task queue
consumer fill absent details for older readers and queued tasks with the same helper, while
preserving details that were already supplied.

Transaction-origin lookup remains deferred. Any future origin metadata belongs in the reader's
shared output, with availability determined by the source chain, rather than in a policy client.
