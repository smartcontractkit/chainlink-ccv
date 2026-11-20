# EVM migration funding and legacy crash containment

CCV does not provide a generic native-transfer funding helper in this change. The supported path for the exceptions below is an NOP-controlled external wallet and the approved chain-specific procedure. Do not treat the legacy `chainlink txs evm create` command as universally supported and do not patch or wait for an upstream CLI change.

## Required funding procedure

Before every transfer, the NOP reviews the chain, source account, destination executor transmitter, exact amount, token, and gas behavior. The wallet must support arbitrary-precision amounts and any required per-call gas limit without an `int64` wei conversion. Signing stays with the NOP: never send a private key to Chainlink Labs, write a new plaintext key export for funding, or place credentials in JD, logs, command output, or artifacts.

Use the reviewed external-wallet procedure for:

- **Mode (34443) and Henesys (68414):** the legacy funding path is unsupported because reported unknown-RPC-error crashes remain undiagnosed.
- **Tempo (4217):** use the approved pathUSD token-funding and fee-token balance-check process; generic native-value transfer does not apply.
- **Hedera (295):** initialize the destination account through the approved Hedera process before funding; a generic EVM transfer is not proof of initialization.
- **zkSync-family chains and Mantle (5000):** use the chain's reviewed custom gas and fee procedure. Do not force the legacy fixed `LimitTransfer` path through by changing reviewed settings.

For other chains, follow the NOP migration guide only after confirming that the standard native-value flow applies. Never use legacy `--wei`: its `int64` parsing can overflow above approximately 9.2 native tokens at 18 decimals. Require a transaction hash, successful receipt, expected sender and recipient, intended amount, and reasonable gas limit before signing off funding.

The Mantle `LimitMultiplier = 1` standalone configuration guard does not change the shared legacy CL configuration and is not a funding-flow fix.

## Panic or crash-loop containment

If legacy funding panics or the container crash-loops:

1. Disable the legacy container restart automation and stop the old node to prevent repeated submissions.
2. Preserve application logs, public transaction hashes, RPC error text, and existing TXM records as evidence. Keep the old database intact for the approved rollback/recovery process.
3. Do not manually edit `evm.txes` or `evm.tx_attempts`, reset nonces, delete the TXM database, or repeatedly rebroadcast. Coordinate an approved recovery with Chainlink Labs.
4. Continue migration funding only through the NOP-controlled external-wallet path after reviewing what was actually submitted and confirmed.

`UnknownErrorRetryTimeout` is a plausible upstream nil path, not a confirmed cause of the Mode/Henesys crashes. For diagnosis, request only the stack trace, exact public legacy image and non-secret config, public transaction hashes, and RPC error text. Never request private keys, database dumps, keystore passwords, export files/passwords, or other secret material. Do not describe this legacy funding failure as a standalone v0.22.0 executor regression.
