# Changelog

## [0.2.0](https://github.com/smartcontractkit/chainlink-ccv/compare/deployment/v0.1.0...deployment/v0.2.0) (2026-08-21)


### Features

* add onramp upgrade verifier config changeset and refactor ApplyVerifierConfig with options ([#1356](https://github.com/smartcontractkit/chainlink-ccv/issues/1356)) ([b740c6d](https://github.com/smartcontractkit/chainlink-ccv/commit/b740c6d6fa7afce3923ca4d04698db77a3c9b0f8))
* **evm:** Derive RMN Remote addresses from ramp contracts' on-chain static config ([#1357](https://github.com/smartcontractkit/chainlink-ccv/issues/1357)) ([32d9d53](https://github.com/smartcontractkit/chainlink-ccv/commit/32d9d534ef3c2d083443b6045f4f649836b0ad65))


### Bug Fixes

* **deps:** bump chain-selectors ([#1347](https://github.com/smartcontractkit/chainlink-ccv/issues/1347)) ([694608e](https://github.com/smartcontractkit/chainlink-ccv/commit/694608e509526c17b9dec1da566c4599655d60a3))
* update lombard and cctp verifier tags to use v2.1.0 ([#1340](https://github.com/smartcontractkit/chainlink-ccv/issues/1340)) ([42174dd](https://github.com/smartcontractkit/chainlink-ccv/commit/42174dd7851db594f319a376caff44747fdfbe4b))

## [0.1.0](https://github.com/smartcontractkit/chainlink-ccv/compare/deployment/v0.0.1...deployment/v0.1.0) (2026-07-30)


### Features

* push signing key variants at JD registration; add family SigningIdentityReader ([#1230](https://github.com/smartcontractkit/chainlink-ccv/issues/1230)) ([b654f20](https://github.com/smartcontractkit/chainlink-ccv/commit/b654f20972d84ff0e40544ceab32a4b871df05a9))
* support JD-free devenvs ([#1257](https://github.com/smartcontractkit/chainlink-ccv/issues/1257)) ([4273608](https://github.com/smartcontractkit/chainlink-ccv/commit/4273608b44ab43b8cdf9cbaf3223bd2333e16767))
* unify JD for CL/standalone devenv flows ([#1264](https://github.com/smartcontractkit/chainlink-ccv/issues/1264)) ([0822fd8](https://github.com/smartcontractkit/chainlink-ccv/commit/0822fd827e1e3108d9e8ffdc8e68878641030a6a))
* verifier + executor bundle changeset ([#1288](https://github.com/smartcontractkit/chainlink-ccv/issues/1288)) ([73e8166](https://github.com/smartcontractkit/chainlink-ccv/commit/73e81665e03ff5c17803234cb803d28de1d56e85))


### Bug Fixes

* **deps:** bump chain-selectors ([#1313](https://github.com/smartcontractkit/chainlink-ccv/issues/1313)) ([6a75095](https://github.com/smartcontractkit/chainlink-ccv/commit/6a75095ee87a361b4fca05cb4a83ec7a71ae77d6))
* **evm:** force canonical signer identity ([#1310](https://github.com/smartcontractkit/chainlink-ccv/issues/1310)) ([620fac7](https://github.com/smartcontractkit/chainlink-ccv/commit/620fac72ead2531328f2efcbba2ecc429bff999f))
* **evm:** onramp lane expansion fixes ([#1306](https://github.com/smartcontractkit/chainlink-ccv/issues/1306)) ([41818c8](https://github.com/smartcontractkit/chainlink-ccv/commit/41818c8843bd522bbb49c076371e334ef3ea0909))
* skip JD chain support validation for non-EVM verifier adapter ([#1308](https://github.com/smartcontractkit/chainlink-ccv/issues/1308)) ([4015d2c](https://github.com/smartcontractkit/chainlink-ccv/commit/4015d2cf3dbf454d2d83c0a769abbddb3d1e068d))
