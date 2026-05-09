# Breaking change: `ImplFactory.New` is deployment-environment first

`github.com/smartcontractkit/chainlink-ccv/build/devenv.ImplFactory` no longer takes `*ccv.Cfg` or `*blockchain.Input` when constructing a `CCIP17` handle.

## Before

```go
New(ctx context.Context, lggr zerolog.Logger, cfg *ccv.Cfg, env *deployment.Environment, bc *blockchain.Input) (cciptestinterfaces.CCIP17, error)
```

## After

```go
New(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (cciptestinterfaces.CCIP17, error)
```

The selector must correspond to a chain present on `env.BlockChains` for the implementation’s family. Implementations resolve RPC/WebSocket URLs (or Canton chain IDs) from the CLDF environment instead of from `blockchain.Input`.

## Migration for downstream repos

1. Update your `RegisterImplFactory` implementation’s `New` method to match the new signature.
2. Obtain chain connectivity from `env` (e.g. `env.BlockChains.EVMChains()[chainSelector]` or your family’s map) rather than from `bc.Out.Nodes`.
3. Keep storing `*ccv.Cfg` on your `Chain` type if you still need devenv-only services (e.g. EDS); only the **factory** path drops `cfg` / `bc` for `New`.
4. Optional convenience in this module: `ccv.NewCCIP17ForChainSelector(ctx, lggr, env, chainSelector)`.

## Coordination

After this lands in `chainlink-ccv`, bump the `chainlink-ccv` module dependency in repos such as `chainlink-canton` and merge the matching factory change in the same window.
