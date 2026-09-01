# Changelog

## [0.7.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.6.0...v0.7.0) (2026-09-01)


### Features

* Signal based job queue ([#1391](https://github.com/smartcontractkit/chainlink-ccv/issues/1391)) ([4d0dcce](https://github.com/smartcontractkit/chainlink-ccv/commit/4d0dcce7c395d019ba67247b06b3f8cdd42bcd52))


### Bug Fixes

* **verifier:** attest using any reachable aggregator's rules ([#1388](https://github.com/smartcontractkit/chainlink-ccv/issues/1388)) ([84b6b7c](https://github.com/smartcontractkit/chainlink-ccv/commit/84b6b7c8dd4ea6d2a15e599b636e0d6cd43d2795))

## [0.6.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.5.0...v0.6.0) (2026-08-28)


### Features

* **evm:** batch block header fetches ([#1381](https://github.com/smartcontractkit/chainlink-ccv/issues/1381)) ([4b7db6f](https://github.com/smartcontractkit/chainlink-ccv/commit/4b7db6f8d6e53a825483be4847357ca1bb9236d1))

## [0.5.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.4.0...v0.5.0) (2026-08-25)


### Features

* Batch chain status updates ([#1373](https://github.com/smartcontractkit/chainlink-ccv/issues/1373)) ([2c733db](https://github.com/smartcontractkit/chainlink-ccv/commit/2c733dbd7182c8951cc31a211bb38bfecf605b97))
* **evm:** Derive RMN Remote addresses from ramp contracts' on-chain static config ([#1357](https://github.com/smartcontractkit/chainlink-ccv/issues/1357)) ([32d9d53](https://github.com/smartcontractkit/chainlink-ccv/commit/32d9d534ef3c2d083443b6045f4f649836b0ad65))
* refactor token verifier factory ([#1365](https://github.com/smartcontractkit/chainlink-ccv/issues/1365)) ([5d5c08c](https://github.com/smartcontractkit/chainlink-ccv/commit/5d5c08cc5b59266a4528a14402f9152567540dd5))
* **standalone:** staging migration prep ([#1369](https://github.com/smartcontractkit/chainlink-ccv/issues/1369)) ([5adf356](https://github.com/smartcontractkit/chainlink-ccv/commit/5adf35643a31dba82c93e29bf5e2ea2add504994))
* token-verifier: Support Solana format for Lombard ([#1366](https://github.com/smartcontractkit/chainlink-ccv/issues/1366)) ([f58abe6](https://github.com/smartcontractkit/chainlink-ccv/commit/f58abe613a63cc80f186274a4f9b6f82aca8d1ae))


### Bug Fixes

* **deps:** bump chain-selectors ([#1347](https://github.com/smartcontractkit/chainlink-ccv/issues/1347)) ([694608e](https://github.com/smartcontractkit/chainlink-ccv/commit/694608e509526c17b9dec1da566c4599655d60a3))
* **evm:** extract load config functionality away from init ([#1375](https://github.com/smartcontractkit/chainlink-ccv/issues/1375)) ([fd4de11](https://github.com/smartcontractkit/chainlink-ccv/commit/fd4de1180dbf90f9e1fed3669c281e2d2add196d))
* **executor:** fail on pyroscope start errors, settle deprecated [Monitoring] ([#1352](https://github.com/smartcontractkit/chainlink-ccv/issues/1352)) ([01a8773](https://github.com/smartcontractkit/chainlink-ccv/commit/01a87733ff1aa7e4f3e61563c46ec4089ac4de08))
* **indexer:** no hmac if empty/default api pair ([#1368](https://github.com/smartcontractkit/chainlink-ccv/issues/1368)) ([00f1fb9](https://github.com/smartcontractkit/chainlink-ccv/commit/00f1fb9a5eeff410e5f360c33ec3e978cb1aa2ed))
* Remove EVM specific address validation for CCTP transaction hash  ([#1371](https://github.com/smartcontractkit/chainlink-ccv/issues/1371)) ([c5fefe6](https://github.com/smartcontractkit/chainlink-ccv/commit/c5fefe6e1d29c26e10821fb67589a93081b747e8))
* **standalone:** executor o11y ([#1349](https://github.com/smartcontractkit/chainlink-ccv/issues/1349)) ([8f97557](https://github.com/smartcontractkit/chainlink-ccv/commit/8f975576ee60d8680c041dbfac073c97e33bdd65))
* **verifier:** unify poll timing, drop dead SourceConfig.RMNRemoteAddress ([#1351](https://github.com/smartcontractkit/chainlink-ccv/issues/1351)) ([eb69b02](https://github.com/smartcontractkit/chainlink-ccv/commit/eb69b02119278da6a24d2be21bc60f367decf998))

## [0.4.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.3.0...v0.4.0) (2026-08-13)


### Features

* **executor:** add pipeline state metrics ([#1339](https://github.com/smartcontractkit/chainlink-ccv/issues/1339)) ([b25bb1a](https://github.com/smartcontractkit/chainlink-ccv/commit/b25bb1a6e9f79ea05daaf17b253a12fc7f7a60a0))
* **verifier:** add message pipeline state metrics ([#1334](https://github.com/smartcontractkit/chainlink-ccv/issues/1334)) ([3f28b1f](https://github.com/smartcontractkit/chainlink-ccv/commit/3f28b1f843029f8cc04091731de7790a7ab90977))


### Bug Fixes

* **evm:** harden standalone cutover parity ([#1343](https://github.com/smartcontractkit/chainlink-ccv/issues/1343)) ([8bff61f](https://github.com/smartcontractkit/chainlink-ccv/commit/8bff61f994cdcec4808ce0c5bbbf4bedeb410c97))
* **evm:** standalone parity items batch 1 ([#1342](https://github.com/smartcontractkit/chainlink-ccv/issues/1342)) ([3da1b7d](https://github.com/smartcontractkit/chainlink-ccv/commit/3da1b7daca4b605e2de9e044a40f914d9ea57848))
* update lombard and cctp verifier tags to use v2.1.0 ([#1340](https://github.com/smartcontractkit/chainlink-ccv/issues/1340)) ([42174dd](https://github.com/smartcontractkit/chainlink-ccv/commit/42174dd7851db594f319a376caff44747fdfbe4b))
* **verifier:** restore standalone source-reader monitoring ([#1345](https://github.com/smartcontractkit/chainlink-ccv/issues/1345)) ([6691a13](https://github.com/smartcontractkit/chainlink-ccv/commit/6691a13783b5295283201f1102d43035cdb1bcfb))

## [0.3.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.2.0...v0.3.0) (2026-08-10)


### Features

* add evm doc generation ([#1312](https://github.com/smartcontractkit/chainlink-ccv/issues/1312)) ([bf4890d](https://github.com/smartcontractkit/chainlink-ccv/commit/bf4890d1793982c6a45bd7b7c69421c3c68b7c66))
* Add KMS support ([#1301](https://github.com/smartcontractkit/chainlink-ccv/issues/1301)) ([89d4e91](https://github.com/smartcontractkit/chainlink-ccv/commit/89d4e910ee5ffdb64d68a4eeefad003b353659f7))
* Backpressure improvements ([#1285](https://github.com/smartcontractkit/chainlink-ccv/issues/1285)) ([44cdcc0](https://github.com/smartcontractkit/chainlink-ccv/commit/44cdcc055b60a6cd4eb0433d92927cfa4095c94b))
* **bootstrap:** adopt Chainlink node keys via [key_import] ([#1317](https://github.com/smartcontractkit/chainlink-ccv/issues/1317)) ([18539d6](https://github.com/smartcontractkit/chainlink-ccv/commit/18539d60fc1d090363c3b6cf95af64b2f1f998ef))
* **cli:** ccv migrate export/inspect commands ([#1320](https://github.com/smartcontractkit/chainlink-ccv/issues/1320)) ([e72f479](https://github.com/smartcontractkit/chainlink-ccv/commit/e72f479c52122c5eec86a2e0b2bea57423644acc))
* **evm:** accept a Chainlink node TOML config in the EVM accessor ([#1321](https://github.com/smartcontractkit/chainlink-ccv/issues/1321)) ([bb329b8](https://github.com/smartcontractkit/chainlink-ccv/commit/bb329b8504cd57f68e5aeba472fe4cef6fb28602))
* **evm:** deprecate CTF from evm standalone ([#1305](https://github.com/smartcontractkit/chainlink-ccv/issues/1305)) ([f72fd9b](https://github.com/smartcontractkit/chainlink-ccv/commit/f72fd9b209e7e03048026437242a543cd354d400))
* **evm:** drive restart-orphaned transactions to completion ([#1332](https://github.com/smartcontractkit/chainlink-ccv/issues/1332)) ([c20ed8a](https://github.com/smartcontractkit/chainlink-ccv/commit/c20ed8ad084b30e7bc504238fa60bd6b0c84e3e1))
* **evm:** support per-node RPC prioritization in the standalone accessor ([#1326](https://github.com/smartcontractkit/chainlink-ccv/issues/1326)) ([35c93df](https://github.com/smartcontractkit/chainlink-ccv/commit/35c93dff2831dfd5ca08efb460e216c3ad8dac45))
* **evm:** use production chain services in standalone accessors ([#1292](https://github.com/smartcontractkit/chainlink-ccv/issues/1292)) ([10f02b0](https://github.com/smartcontractkit/chainlink-ccv/commit/10f02b07feb54c46ced9413ca127a4d57a718533))
* **executor:** Add ErrMessageRejectedByTransmitter to executor non retryable errors ([#1330](https://github.com/smartcontractkit/chainlink-ccv/issues/1330)) ([92f44ec](https://github.com/smartcontractkit/chainlink-ccv/commit/92f44ec95a9da828c19490eeadc91b292b3cf3ca))
* Make the CSA key mode/backend-driven ([#1322](https://github.com/smartcontractkit/chainlink-ccv/issues/1322)) ([d8bcf56](https://github.com/smartcontractkit/chainlink-ccv/commit/d8bcf56adae5972c7f7dc654a9946a6cbb90f053))
* **migration:** node key export shared between CLI and devenv ([#1318](https://github.com/smartcontractkit/chainlink-ccv/issues/1318)) ([7ea702e](https://github.com/smartcontractkit/chainlink-ccv/commit/7ea702ecae863efcb9e95c9deb735d0034fc793f))
* Remove blocking mechanism in enqueue ([#1298](https://github.com/smartcontractkit/chainlink-ccv/issues/1298)) ([ff0e27d](https://github.com/smartcontractkit/chainlink-ccv/commit/ff0e27d4391e7c4d9938c46d6f505bd9d71b2aed))
* Use redis for heartbeat config ([#1284](https://github.com/smartcontractkit/chainlink-ccv/issues/1284)) ([c2352c5](https://github.com/smartcontractkit/chainlink-ccv/commit/c2352c521f6e969121797e6d8efda4e7e035c3ac))
* verifier & executor traces (CCIP-12516) ([#1297](https://github.com/smartcontractkit/chainlink-ccv/issues/1297)) ([669bb6e](https://github.com/smartcontractkit/chainlink-ccv/commit/669bb6e63021da14d7611b815ed098fa377c7f5c))


### Bug Fixes

* **configdoc:** error on nil fields in example config ([#1311](https://github.com/smartcontractkit/chainlink-ccv/issues/1311)) ([408abc4](https://github.com/smartcontractkit/chainlink-ccv/commit/408abc41060560a575a01a457a13d20e4a392af2))
* **deps:** bump chain-selectors ([#1313](https://github.com/smartcontractkit/chainlink-ccv/issues/1313)) ([6a75095](https://github.com/smartcontractkit/chainlink-ccv/commit/6a75095ee87a361b4fca05cb4a83ec7a71ae77d6))
* **evm:** onramp lane expansion fixes ([#1306](https://github.com/smartcontractkit/chainlink-ccv/issues/1306)) ([41818c8](https://github.com/smartcontractkit/chainlink-ccv/commit/41818c8843bd522bbb49c076371e334ef3ea0909))
* Revert "feat: Backpressure improvements" ([#1296](https://github.com/smartcontractkit/chainlink-ccv/issues/1296)) ([6b42ff1](https://github.com/smartcontractkit/chainlink-ccv/commit/6b42ff14db43c4c0dabe8efa45d97ad6ad2644e0))

## [0.2.0](https://github.com/smartcontractkit/chainlink-ccv/compare/v0.1.0...v0.2.0) (2026-07-20)


### ⚠ BREAKING CHANGES

* remove blockchain_infos from application config (CCIP-12443) ([#1271](https://github.com/smartcontractkit/chainlink-ccv/issues/1271))

### Features

* **jd:** stage replacement jobs before cutover (CCIP-11875) ([#1270](https://github.com/smartcontractkit/chainlink-ccv/issues/1270)) ([ec7a327](https://github.com/smartcontractkit/chainlink-ccv/commit/ec7a327d5e17efd21f20ae32ee9bd5d171921ac1))
* push signing key variants at JD registration; add family SigningIdentityReader ([#1230](https://github.com/smartcontractkit/chainlink-ccv/issues/1230)) ([b654f20](https://github.com/smartcontractkit/chainlink-ccv/commit/b654f20972d84ff0e40544ceab32a4b871df05a9))
* remove blockchain_infos from application config (CCIP-12443) ([#1271](https://github.com/smartcontractkit/chainlink-ccv/issues/1271)) ([2b5159a](https://github.com/smartcontractkit/chainlink-ccv/commit/2b5159afb28f5b6de74815940faf2468e1c51c3f))
* use config instead of blockchain info ([#1267](https://github.com/smartcontractkit/chainlink-ccv/issues/1267)) ([3ac5492](https://github.com/smartcontractkit/chainlink-ccv/commit/3ac54920dd0862401c3779fd87eca26f4018e24e))


### Bug Fixes

* Initialize lastSeenTime to InitialQueryTime ([#1275](https://github.com/smartcontractkit/chainlink-ccv/issues/1275)) ([d938b37](https://github.com/smartcontractkit/chainlink-ccv/commit/d938b371c5d69374ee0c03c1ae61a76ba81b7c2a))

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
