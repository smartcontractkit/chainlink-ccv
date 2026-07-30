# Changelog

## [0.3.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.2.0...build/devenv/v0.3.0) (2026-07-30)


### ⚠ BREAKING CHANGES

* **devenv:** expose src/dest tx hashes in tcapi run results ([#1289](https://github.com/smartcontractkit/chainlink-ccv/issues/1289))
* **devenv:** use narrower chain interfaces in tcapi ([#1281](https://github.com/smartcontractkit/chainlink-ccv/issues/1281))

### Features

* Add KMS support ([#1301](https://github.com/smartcontractkit/chainlink-ccv/issues/1301)) ([89d4e91](https://github.com/smartcontractkit/chainlink-ccv/commit/89d4e910ee5ffdb64d68a4eeefad003b353659f7))
* Backpressure improvements ([#1285](https://github.com/smartcontractkit/chainlink-ccv/issues/1285)) ([44cdcc0](https://github.com/smartcontractkit/chainlink-ccv/commit/44cdcc055b60a6cd4eb0433d92927cfa4095c94b))
* **devenv:** expose src/dest tx hashes in tcapi run results ([#1289](https://github.com/smartcontractkit/chainlink-ccv/issues/1289)) ([cb90ee4](https://github.com/smartcontractkit/chainlink-ccv/commit/cb90ee49ef8d052093e7ec85cc325e5788dff71b))
* **devenv:** use narrower chain interfaces in tcapi ([#1281](https://github.com/smartcontractkit/chainlink-ccv/issues/1281)) ([9002411](https://github.com/smartcontractkit/chainlink-ccv/commit/9002411014bbed57a7bb1a01669a559c01c74769))
* **evm:** deprecate CTF from evm standalone ([#1305](https://github.com/smartcontractkit/chainlink-ccv/issues/1305)) ([f72fd9b](https://github.com/smartcontractkit/chainlink-ccv/commit/f72fd9b209e7e03048026437242a543cd354d400))
* **evm:** RPC failover in standalone accessors ([#1299](https://github.com/smartcontractkit/chainlink-ccv/issues/1299)) ([46b6c7a](https://github.com/smartcontractkit/chainlink-ccv/commit/46b6c7ad820d2b80b14d44bfe4e71992a6286461))
* **evm:** use production chain services in standalone accessors ([#1292](https://github.com/smartcontractkit/chainlink-ccv/issues/1292)) ([10f02b0](https://github.com/smartcontractkit/chainlink-ccv/commit/10f02b07feb54c46ced9413ca127a4d57a718533))
* migrate chaos tests to e2e/chaos package and V3 RunScenario ([#1226](https://github.com/smartcontractkit/chainlink-ccv/issues/1226)) ([a0fde4d](https://github.com/smartcontractkit/chainlink-ccv/commit/a0fde4d69fe06522acd7b931718f9fec83d8496a))
* Remove blocking mechanism in enqueue ([#1298](https://github.com/smartcontractkit/chainlink-ccv/issues/1298)) ([ff0e27d](https://github.com/smartcontractkit/chainlink-ccv/commit/ff0e27d4391e7c4d9938c46d6f505bd9d71b2aed))
* Use redis for heartbeat config ([#1284](https://github.com/smartcontractkit/chainlink-ccv/issues/1284)) ([c2352c5](https://github.com/smartcontractkit/chainlink-ccv/commit/c2352c521f6e969121797e6d8efda4e7e035c3ac))


### Bug Fixes

* **deps:** bump chain-selectors ([#1313](https://github.com/smartcontractkit/chainlink-ccv/issues/1313)) ([6a75095](https://github.com/smartcontractkit/chainlink-ccv/commit/6a75095ee87a361b4fca05cb4a83ec7a71ae77d6))
* **evm:** onramp lane expansion fixes ([#1306](https://github.com/smartcontractkit/chainlink-ccv/issues/1306)) ([41818c8](https://github.com/smartcontractkit/chainlink-ccv/commit/41818c8843bd522bbb49c076371e334ef3ea0909))
* replace the empty executor args and token args with real optional params ([#1300](https://github.com/smartcontractkit/chainlink-ccv/issues/1300)) ([23bba21](https://github.com/smartcontractkit/chainlink-ccv/commit/23bba213dfd737157e3418457dc92173e82d452b))
* Revert "feat: Backpressure improvements" ([#1296](https://github.com/smartcontractkit/chainlink-ccv/issues/1296)) ([6b42ff1](https://github.com/smartcontractkit/chainlink-ccv/commit/6b42ff14db43c4c0dabe8efa45d97ad6ad2644e0))

## [0.2.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.1.0...build/devenv/v0.2.0) (2026-07-20)


### ⚠ BREAKING CHANGES

* remove blockchain_infos from application config (CCIP-12443) ([#1271](https://github.com/smartcontractkit/chainlink-ccv/issues/1271))

### Features

* **devenv:** less verbose "ccv up" ([#1244](https://github.com/smartcontractkit/chainlink-ccv/issues/1244)) ([c4567d7](https://github.com/smartcontractkit/chainlink-ccv/commit/c4567d77f9df7cf395f0b7914d928c469496502a))
* remove blockchain_infos from application config (CCIP-12443) ([#1271](https://github.com/smartcontractkit/chainlink-ccv/issues/1271)) ([2b5159a](https://github.com/smartcontractkit/chainlink-ccv/commit/2b5159afb28f5b6de74815940faf2468e1c51c3f))

## [0.1.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.0.1...build/devenv/v0.1.0) (2026-07-16)


### ⚠ BREAKING CHANGES

* **bootstrap:** prune With* options in favor of config ([#1265](https://github.com/smartcontractkit/chainlink-ccv/issues/1265))

### Features

* **devenv/tcapi:** bound persistent-network event scans, add delivery-only Run mode ([#1221](https://github.com/smartcontractkit/chainlink-ccv/issues/1221)) ([60f7260](https://github.com/smartcontractkit/chainlink-ccv/commit/60f72600d913b9d2a424fc4ae756c8744d569e99))
* **devenv:** add LockRelease 1.6.1 token pool support  ([#1136](https://github.com/smartcontractkit/chainlink-ccv/issues/1136)) ([850b108](https://github.com/smartcontractkit/chainlink-ccv/commit/850b108a2623f0f75be9f2ae80522adc90531ec6))
* support JD-free devenvs ([#1257](https://github.com/smartcontractkit/chainlink-ccv/issues/1257)) ([4273608](https://github.com/smartcontractkit/chainlink-ccv/commit/4273608b44ab43b8cdf9cbaf3223bd2333e16767))
* unify JD for CL/standalone devenv flows ([#1264](https://github.com/smartcontractkit/chainlink-ccv/issues/1264)) ([0822fd8](https://github.com/smartcontractkit/chainlink-ccv/commit/0822fd827e1e3108d9e8ffdc8e68878641030a6a))
* use config instead of blockchain info ([#1267](https://github.com/smartcontractkit/chainlink-ccv/issues/1267)) ([3ac5492](https://github.com/smartcontractkit/chainlink-ccv/commit/3ac54920dd0862401c3779fd87eca26f4018e24e))


### Bug Fixes

* update ingestion timestamp on message replay/redelivery ([#1173](https://github.com/smartcontractkit/chainlink-ccv/issues/1173)) ([1951128](https://github.com/smartcontractkit/chainlink-ccv/commit/1951128abf2e556591f4824565b7e622c14cc24c))
* verifier target label ([#1200](https://github.com/smartcontractkit/chainlink-ccv/issues/1200)) ([7e4917a](https://github.com/smartcontractkit/chainlink-ccv/commit/7e4917ac4f0d1e3a747c3f8c4643e6208b268cf8))


### Code Refactoring

* **bootstrap:** prune With* options in favor of config ([#1265](https://github.com/smartcontractkit/chainlink-ccv/issues/1265)) ([931cc17](https://github.com/smartcontractkit/chainlink-ccv/commit/931cc17a239f992ae49c19f0dcbc20ee0b2e5b8b))
