# Changelog

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
