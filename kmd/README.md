# kmd

`kmd` is a key management daemon that wraps the chainlink-common [`keystore`](https://github.com/smartcontractkit/chainlink-common/blob/c7d66f2dab434297e0b299e7445b7e40d0b2826e/keystore/keystore.go#L165-L170) API with an HTTP API.

The intention is for a singular `kmd` to support potentially many CCIP applications (CCVs or executors). The `kmd` can manage any kind
of key that the underlying keystore can manage, which as of writing the relevant keys are Secp256k1 for ECDSA signatures and Ed25519
for JD communication.

# Client

The `kmd` Client is intended to be used by applications that require key-related operations, most significantly signing.
