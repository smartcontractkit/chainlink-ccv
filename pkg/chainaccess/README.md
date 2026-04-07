# Chain Access Layer
Provides a way to inject family specific access implementations into CCIP services.

# Registry
A way to access instantiations of the chainaccess.Accessor object for a chain family.

Applications register a constructor that accepts a simple config string.

# Configuration
There are cases where the Accessor configuration overlaps with App configuration. one
example is the OnRamp address which is needed by chainaccess.SourceReader and the
CommitteeVerifier. To account for this, the accessor configuration is treated as an
overlay with the App configuration.

In order to add an accessor interface, the App needs the following:
1. The app config includes "blockchain_infos" along with the app config:
```go
type ConfigWithBlockchainInfos struct {
    MyAppConfig       // note: there is no struct tag so config is at the top level.
	MyAppSharedConfig // note: this could be embedded in MyAppConfig.
    BlockchainInfos Infos[string] `toml:"blockchain_infos"`
}
```
2. The app adds its shared configuration to `pkg/chainaccess`:
```go
type MyAppSharedConfig struct {
    OnRampAddress string `toml:"on_ramp_address"`
}
```
3. The shared configuration is added to the GenericConfig struct:
```go
type GenericConfig struct {
    ChainConfig Infos[string] `toml:"blockchain_infos"`
    CommitteeConfig
}
```
4. Each chain family implementation registers itself, so at this point the app simply creates the registry by passing in its app config:
```go
chainAccessRegistry := chainaccess.NewRegistry(os.MustReadFile("config.toml"))
accessor, err := chainAccessRegistry.GetAccessor(lggr, chainsel.ETHEREUM_MAINNET)
```