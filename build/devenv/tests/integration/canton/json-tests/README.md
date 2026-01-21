## Test Daml Contract

This folder holds a small Daml project that can be used to test the Canton source reader.

## Setup

Make sure to [install dpm](https://docs.digitalasset.com/build/3.4/dpm/dpm.html). Once that is installed,
any changes made can be built with:

```
dpm build
```

Make sure to replace the existing `json-tests-0.0.1.dar` with the newly built DAR, which will be placed in 
.daml/dist/json-tests-0.0.1.dar.

## Contract Description

The `TestRouter` contract has only a single choice `CCIPSend` which "emits" a CCIPMessageSent
event with the provided arguments.

These arguments currently match what is currently being developed in the [real](https://github.com/smartcontractkit/chainlink-canton-internal/blob/cef577411578904a28fb6364e4ff1d3eecffc4d3/contracts/ccip/perpartyrouter/daml/CCIP/PerPartyRouter.daml#L137-L147) CCIP Canton
contracts.
