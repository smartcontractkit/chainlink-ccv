# Changelog

## [0.6.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.5.0...build/devenv/v0.6.0) (2026-09-04)


### ⚠ BREAKING CHANGES

* **devenv:** declarative token pairing ([#1405](https://github.com/smartcontractkit/chainlink-ccv/issues/1405))

### Features

* **devenv:** declarative token pairing ([#1405](https://github.com/smartcontractkit/chainlink-ccv/issues/1405)) ([0be567c](https://github.com/smartcontractkit/chainlink-ccv/commit/0be567ccfeb9aec4ce4a08dadcda01e0144d050f))
* **devenv:** gas limit support + NewTokenCombinationFromRefs ([#1398](https://github.com/smartcontractkit/chainlink-ccv/issues/1398)) ([3c7d1ce](https://github.com/smartcontractkit/chainlink-ccv/commit/3c7d1cef9c36bc4da75d251db7dcf6e9ffbb552a))
* **verifier:** policy hooks ([#1380](https://github.com/smartcontractkit/chainlink-ccv/issues/1380)) ([039ff50](https://github.com/smartcontractkit/chainlink-ccv/commit/039ff507b30c5d31a32f8745f5a82f4efca392ad))

## [0.5.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.4.0...build/devenv/v0.5.0) (2026-08-31)


### Features

* Batch chain status updates ([#1373](https://github.com/smartcontractkit/chainlink-ccv/issues/1373)) ([2c733db](https://github.com/smartcontractkit/chainlink-ccv/commit/2c733dbd7182c8951cc31a211bb38bfecf605b97))
* devenv: Allow setting token verifier modifiers ([#1379](https://github.com/smartcontractkit/chainlink-ccv/issues/1379)) ([7fd4cfe](https://github.com/smartcontractkit/chainlink-ccv/commit/7fd4cfe03ca03c9f051348539f86c158e7a98b4f))
* **devenv:** agnostic infra for failover tests ([#1378](https://github.com/smartcontractkit/chainlink-ccv/issues/1378)) ([a066cf5](https://github.com/smartcontractkit/chainlink-ccv/commit/a066cf58abb015a4fdaf91a6875964a1e3ac7a87))
* Scope config to chains for that verifier's chain family ([#1384](https://github.com/smartcontractkit/chainlink-ccv/issues/1384)) ([49be32a](https://github.com/smartcontractkit/chainlink-ccv/commit/49be32a9332eb43df343e4291a7254f0ddb6b18e))

## [0.4.0](https://github.com/smartcontractkit/chainlink-ccv/compare/build/devenv/v0.3.0...build/devenv/v0.4.0) (2026-08-21)


### Features

* add evm fire-forget flag ([#1359](https://github.com/smartcontractkit/chainlink-ccv/issues/1359)) ([40b5304](https://github.com/smartcontractkit/chainlink-ccv/commit/40b5304d670fecfd03d7f586e4fafc4e0803dfde))
* add onramp upgrade verifier config changeset and refactor ApplyVerifierConfig with options ([#1356](https://github.com/smartcontractkit/chainlink-ccv/issues/1356)) ([b740c6d](https://github.com/smartcontractkit/chainlink-ccv/commit/b740c6d6fa7afce3923ca4d04698db77a3c9b0f8))
* bump verifier_executor.json dash w/ new panels ([#1337](https://github.com/smartcontractkit/chainlink-ccv/issues/1337)) ([870200f](https://github.com/smartcontractkit/chainlink-ccv/commit/870200f58cb67508a6ef930092f4cbac01601a3b))
* **cli:** ccv migrate export/inspect commands ([#1320](https://github.com/smartcontractkit/chainlink-ccv/issues/1320)) ([e72f479](https://github.com/smartcontractkit/chainlink-ccv/commit/e72f479c52122c5eec86a2e0b2bea57423644acc))
* **devenv:** CL-to-standalone cutover tooling and migration e2e ([#1319](https://github.com/smartcontractkit/chainlink-ccv/issues/1319)) ([e8cbe91](https://github.com/smartcontractkit/chainlink-ccv/commit/e8cbe91f55bb31829ff8f804a089b8c84058501c))
* **evm:** Derive RMN Remote addresses from ramp contracts' on-chain static config ([#1357](https://github.com/smartcontractkit/chainlink-ccv/issues/1357)) ([32d9d53](https://github.com/smartcontractkit/chainlink-ccv/commit/32d9d534ef3c2d083443b6045f4f649836b0ad65))
* **evm:** drive restart-orphaned transactions to completion ([#1332](https://github.com/smartcontractkit/chainlink-ccv/issues/1332)) ([c20ed8a](https://github.com/smartcontractkit/chainlink-ccv/commit/c20ed8ad084b30e7bc504238fa60bd6b0c84e3e1))
* **executor:** add pipeline state metrics ([#1339](https://github.com/smartcontractkit/chainlink-ccv/issues/1339)) ([b25bb1a](https://github.com/smartcontractkit/chainlink-ccv/commit/b25bb1a6e9f79ea05daaf17b253a12fc7f7a60a0))
* Make the CSA key mode/backend-driven ([#1322](https://github.com/smartcontractkit/chainlink-ccv/issues/1322)) ([d8bcf56](https://github.com/smartcontractkit/chainlink-ccv/commit/d8bcf56adae5972c7f7dc654a9946a6cbb90f053))


### Bug Fixes

* bump ccip, fix RMN refs ([#1335](https://github.com/smartcontractkit/chainlink-ccv/issues/1335)) ([ec35bc0](https://github.com/smartcontractkit/chainlink-ccv/commit/ec35bc0213d36e160e1f59db2286eb8fe07352b0))
* **deps:** bump chain-selectors ([#1347](https://github.com/smartcontractkit/chainlink-ccv/issues/1347)) ([694608e](https://github.com/smartcontractkit/chainlink-ccv/commit/694608e509526c17b9dec1da566c4599655d60a3))
* **devenv:** retry tx receipt fetch with exponential backoff ([#1361](https://github.com/smartcontractkit/chainlink-ccv/issues/1361)) ([348cf20](https://github.com/smartcontractkit/chainlink-ccv/commit/348cf204a17ebdd945f356a5eb4f3ef52923112b))
* **evm:** harden standalone cutover parity ([#1343](https://github.com/smartcontractkit/chainlink-ccv/issues/1343)) ([8bff61f](https://github.com/smartcontractkit/chainlink-ccv/commit/8bff61f994cdcec4808ce0c5bbbf4bedeb410c97))
* update lombard and cctp verifier tags to use v2.1.0 ([#1340](https://github.com/smartcontractkit/chainlink-ccv/issues/1340)) ([42174dd](https://github.com/smartcontractkit/chainlink-ccv/commit/42174dd7851db594f319a376caff44747fdfbe4b))

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
