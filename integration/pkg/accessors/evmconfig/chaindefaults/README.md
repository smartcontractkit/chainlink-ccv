# Embedded EVM chain defaults

The verifier and executor resolve each EVM chain's defaults the way a Chainlink `ccip` node image
does, from two layers embedded in the binary (`../chaindefaults.go`):

- `chainlink-evm/`: chainlink-evm's built-in defaults (`pkg/config/toml/defaults`), at the version
  go.mod links.
- `ccip/`: CCIP's overrides (`ccip/config/evm` in smartcontractkit/chainlink), which the `ccip` image
  applies with `CL_CHAIN_DEFAULTS=/ccip-config`.

A chain gets CCIP's `fallback.toml`, then chainlink-evm's file for its chain ID, then CCIP's file for
it. A file or key that does not load is skipped and named in a startup warning; it never stops the
process. Both directories are copies; do not edit them by hand.

chainlink-evm source: github.com/smartcontractkit/chainlink-evm@v0.3.4-0.20260915165527-3701875605f4
CCIP source: smartcontractkit/chainlink@8c20b1c4d94ff915d5133c949da9257e296ec41e (2026-10-30)

Refresh chainlink-evm's layer after bumping it in go.mod, and CCIP's from a chainlink branch, tag, or
full commit SHA:

```sh
just sync-chain-defaults          # chainlink-evm's layer only
just sync-chain-defaults <ref>    # both layers
```

`TestEmbeddedChainlinkEVMDefaultsMatchTheLinkedModule` fails after a chainlink-evm bump until the
first command runs. `TestChainDefaultsMatchACCIPNodeImage` checks the layering against chainlink-evm's
own `CL_CHAIN_DEFAULTS` loading for every chain.
