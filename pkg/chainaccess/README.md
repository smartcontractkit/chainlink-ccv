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
