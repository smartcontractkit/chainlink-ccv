# Changelog

## [0.1.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.0.1...v0.1.0) (2026-07-14)


### ⚠ BREAKING CHANGES

* **bootstrap:** prune With* options in favor of config ([#1265](https://github.com/smartcontractkit/chainlink-ccv/issues/1265))

### Features

* consolidate verifier config ([#1213](https://github.com/smartcontractkit/chainlink-ccv/issues/1213)) ([660cccb](https://github.com/smartcontractkit/chainlink-ccv/commit/660cccbf112c85a1acbfc55753a5a348c5b96acb))
* ensure envar is not defaulted if missing ([660cccb](https://github.com/smartcontractkit/chainlink-ccv/commit/660cccbf112c85a1acbfc55753a5a348c5b96acb))
* ensure envar is not defaulted if missing ([660cccb](https://github.com/smartcontractkit/chainlink-ccv/commit/660cccbf112c85a1acbfc55753a5a348c5b96acb))
* **executor:** attach CCIP messageID to TXM transaction meta ([690f203](https://github.com/smartcontractkit/chainlink-ccv/commit/690f2037e6bee959091b5ac551d340165c2a7ee9))
* **executor:** attach CCIP messageID to TXM transaction meta (CCIP-11890) ([#1242](https://github.com/smartcontractkit/chainlink-ccv/issues/1242)) ([690f203](https://github.com/smartcontractkit/chainlink-ccv/commit/690f2037e6bee959091b5ac551d340165c2a7ee9))
* **jd-lifecycle:** instrument job proposal error paths ([#1260](https://github.com/smartcontractkit/chainlink-ccv/issues/1260)) ([b04a2f1](https://github.com/smartcontractkit/chainlink-ccv/commit/b04a2f1f568383c78097ba634c05693bbf4c1a2e))
* parallelise attestation fetching and verification ([#1209](https://github.com/smartcontractkit/chainlink-ccv/issues/1209)) ([976073d](https://github.com/smartcontractkit/chainlink-ccv/commit/976073d878d40fec4ab960fec305e467abbcafba))
* support JD-free devenvs ([#1257](https://github.com/smartcontractkit/chainlink-ccv/issues/1257)) ([4273608](https://github.com/smartcontractkit/chainlink-ccv/commit/4273608b44ab43b8cdf9cbaf3223bd2333e16767))


### Bug Fixes

* api middleware ignore unknown paths ([#1161](https://github.com/smartcontractkit/chainlink-ccv/issues/1161)) ([1012aca](https://github.com/smartcontractkit/chainlink-ccv/commit/1012acac526a458e56d6247a9fb82275acae59e9))
* cap finality_checker fetch range to MaxFinalityBlocksStored ([#1112](https://github.com/smartcontractkit/chainlink-ccv/issues/1112)) ([41c305b](https://github.com/smartcontractkit/chainlink-ccv/commit/41c305bc58b5dc71bab113bfced749d48866df6f))
* ignore unknown monitoring in app config ([#1241](https://github.com/smartcontractkit/chainlink-ccv/issues/1241)) ([315e8ef](https://github.com/smartcontractkit/chainlink-ccv/commit/315e8efeab50966559a3649ba13ea568a1797868))
* Increase fee limit to compensate for EIP-150 gas attenuation ([#1139](https://github.com/smartcontractkit/chainlink-ccv/issues/1139)) ([d99b5c6](https://github.com/smartcontractkit/chainlink-ccv/commit/d99b5c6434be330f1b495dfb93e9ada9975e3b23))
* tmp no strict bootstrap config parsing ([#1232](https://github.com/smartcontractkit/chainlink-ccv/issues/1232)) ([f565685](https://github.com/smartcontractkit/chainlink-ccv/commit/f56568515e8ad749f71e437342fa170f4ec12a0b))
* update ingestion timestamp on message replay/redelivery ([#1173](https://github.com/smartcontractkit/chainlink-ccv/issues/1173)) ([1951128](https://github.com/smartcontractkit/chainlink-ccv/commit/1951128abf2e556591f4824565b7e622c14cc24c))
* verifier target label ([#1200](https://github.com/smartcontractkit/chainlink-ccv/issues/1200)) ([7e4917a](https://github.com/smartcontractkit/chainlink-ccv/commit/7e4917ac4f0d1e3a747c3f8c4643e6208b268cf8))


### Code Refactoring

* **bootstrap:** prune With* options in favor of config ([#1265](https://github.com/smartcontractkit/chainlink-ccv/issues/1265)) ([931cc17](https://github.com/smartcontractkit/chainlink-ccv/commit/931cc17a239f992ae49c19f0dcbc20ee0b2e5b8b))
