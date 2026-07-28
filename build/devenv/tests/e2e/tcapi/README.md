# tcapi — Test Case API

`tcapi` defines standard, chain-agnostic end-to-end test cases for CCIP message delivery
(V3 messaging, token transfers, and related scenarios) that run unchanged across every
chain family in devenv. A chain family plugs in by implementing a small set of Go
interfaces; `tcapi` takes care of building, sending, and confirming messages, and
asserting on aggregator/indexer/executor state.

## Table of Contents

- [Why tcapi exists](#why-tcapi-exists)
- [Design principles](#design-principles)
  - [Universal vs. per-test-case capabilities](#universal-vs-per-test-case-capabilities)
  - [TestCase lifecycle: HavePrerequisites, Run, hydration](#testcase-lifecycle-haveprerequisites-run-hydration)
- [Quickstart: plugging in a new chain family](#quickstart-plugging-in-a-new-chain-family)
  - [1. Implement V3Source and/or V3Destination](#1-implement-v3source-andor-v3destination)
  - [2. Register factories with chainreg](#2-register-factories-with-chainreg)
  - [3. Implement optional capabilities as needed](#3-implement-optional-capabilities-as-needed)
  - [4. Run the standard test suite](#4-run-the-standard-test-suite)
- [Interface reference](#interface-reference)

## Why tcapi exists

The main reason `tcapi` exists is so that end-to-end test cases don't have to be rewritten
per chain family. An e2e test asserts *product* logic (CCIP), not chain-specific
implementation details: a message was confirmed sent on the source chain, it was
successfully verified by the offchain verifiers (checked via aggregator and indexer
assertions, where available), and it was executed successfully on the destination chain.
None of that depends on which chain family is involved — it's the same product behavior
whether the source is EVM, Solana, or Canton. `tcapi` test cases assert only at this
product level, so the same test case works unmodified across every chain family, as long
as that family implements the narrow interfaces `tcapi` needs (see below).

A direct consequence of this is **identical product-level test coverage across every chain
family**. A new chain family doesn't have to figure out what e2e coverage it needs — it
imports and runs the same standard suite (`basic`, `token_transfer`, ...) that every other
family runs, and gets the same guarantees.

`tcapi` is also designed to be **environment agnostic**: the same test case can run against
an ephemeral environment spun up by devenv, or against a live environment pointed at a real
testnet or mainnet. The common access point is a `*deployment.Environment`, which can back
either kind of environment — `tcapi` test cases only ever go through that (plus the chain
interfaces resolved from it), so they don't need to know or care which kind of environment
they're running against.

Before `tcapi`, writing an e2e test for a new chain family also meant implementing
`cciptestinterfaces.CCIP17` in full — every method needed by every product surface
(deployment, configuration, funding, metrics, message sending, message receiving) — before
a single test case could run. That's a large upfront cost for a chain family that only
wants to validate "can I send/receive a V3 CCIP message correctly." `tcapi` decouples
*running the standard test cases* from *implementing the full protocol surface*: a chain
family that only implements message send/receive can register just that, and immediately
get access to the same test cases that fully-onboarded families use.

## Design principles

### Universal vs. per-test-case capabilities

`tcapi` test cases operate on two narrow interfaces:

- `cciptestinterfaces.V3Source` — capable of originating a V3 message.
- `cciptestinterfaces.V3Destination` — capable of receiving a V3 message.

These cover only what *every* V3 test case needs (build/send/confirm on the source side,
receive/confirm on the destination side). Capabilities needed by only *some* test cases —
reading a token balance, reporting a sender address, reporting the max message data size,
advancing blocks, simulating a reorg — are **not** part of these interfaces. Instead they're
small, standalone, optional interfaces (`TokenBalanceReader`, `SenderAddressProvider`,
`MaxDataSizeProvider`, `ProgressableChain`, `ReorgableChain`, ...) that test cases type-assert
at the point of use, skipping (via `HavePrerequisites`) or erroring clearly when the
implementation doesn't support them.

This means a chain family only has to implement what its test suite actually exercises. A
family that never runs token-transfer tests never needs `TokenBalanceReader`.

### TestCase lifecycle: HavePrerequisites, Run, hydration

`TestCase` is not meant to be implemented outside of the `tcapi` package — it's not an
extension point for chain families. Every standard test case (in `tcapi`'s subpackages,
e.g. `basic`, `token_transfer`) already implements it:

```go
type TestCase interface {
	Name() string
	Run(ctx context.Context) error
	HavePrerequisites(ctx context.Context) bool
}
```

If you find yourself wanting a new *kind* of test case (a new product-level scenario, not
a new chain family), it belongs alongside the existing ones as a new `tcapi` subpackage or
file, so it's immediately available to every chain family — not implemented ad hoc by a
single family's test code. Plugging in a new chain family (the focus of this quickstart)
never requires writing a `TestCase`; it only requires implementing the chain interfaces
below so the *existing* test cases can run against it.

The existing standard test categories live as subpackages:
- `tcapi/basic` — V3 messaging scenarios (EOA/contract receivers, single/multi-verifier, max data size)
- `tcapi/token_transfer` — token transfer scenarios across token pool combinations
- `tcapi/chaos` — outage-recovery scenarios (Pumba container stop + V3 lifecycle)

- **Hydration** is the one-time process of resolving environment-specific handles (contract
  addresses, chain resolvers, computed values like max data size) into the test case's
  fields. It's triggered by either `HavePrerequisites` or `Run` — whichever runs first —
  and its result is cached, so a later call to the other method reuses it.
- **HavePrerequisites** reports whether the current environment has everything the test
  case needs (e.g. a contract not deployed, or a chain that doesn't implement an optional
  capability the test needs). Returning `false` skips the test without failing it.
- **Run** executes the test case. It re-runs hydration only if it hasn't already succeeded.

## Quickstart: plugging in a new chain family

### 1. Implement V3Source and/or V3Destination

Implement whichever side(s) your chain family supports:

```go
// cciptestinterfaces.V3Source
type V3Source interface {
	MessageV3Source // BuildV3ExtraArgs
	ChainAsSource    // BuildChainMessage, SendChainMessage, ConfirmSendOnSource, ChainSelector
}

// cciptestinterfaces.V3Destination
type V3Destination interface {
	MessageV3Destination // GetExecutorArgs, GetTokenReceiver, GetTokenArgs
	ChainAsDestination   // GetEOAReceiverAddress, ConfirmExecOnDest, ChainSelector
}
```

You do not need to implement `cciptestinterfaces.CCIP17` or `chainreg.ImplFactory` to do
this — any type satisfying these two interfaces is enough.

**Reference:** EVM's implementation lives in `build/devenv/evm/impl.go`. Its `*CCIP17EVM`
type (constructed via `NewCCIP17EVM`) currently implements the full `CCIP17` interface —
including `V3Source` and `V3Destination` — as one large object; there's no dedicated
narrower EVM type yet. That's an artifact of EVM predating this narrowing, not a
requirement: a new chain family should implement only what it needs, using EVM only as a
reference for method signatures and behavior (e.g. `BuildV3ExtraArgs`, `BuildChainMessage`,
`ConfirmSendOnSource`, `ConfirmExecOnDest`), not as a structural template to copy. If/when
EVM is refactored into narrower types, this doc will be updated to point at those instead.

### 2. Register factories with chainreg

Register constructor functions with `chainreg` so `tcapi` can resolve your chain by
selector at test time:

```go
func init() {
	chainreg.Register(chainsel.FamilyExample, chainreg.Registration{
		V3SourceFactory:      NewV3Source,
		V3DestinationFactory: NewV3Destination,
		// ... other optional Registration fields as needed (see chainreg.Registration)
	})
}

func NewV3Source(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (cciptestinterfaces.V3Source, error) {
	return NewExampleChain(ctx, lggr, env, chainSelector)
}

func NewV3Destination(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (cciptestinterfaces.V3Destination, error) {
	return NewExampleChain(ctx, lggr, env, chainSelector)
}
```

`ccv.Lib.V3Source`/`ccv.Lib.V3Destination` look up these factories first, falling back to
the legacy `ChainsMap`-based full-`CCIP17` resolution if a family hasn't registered one.

**Reference:** `build/devenv/evm/registration.go`'s `init()` registers EVM's
`chainreg.Registration`, including `V3SourceFactory: NewV3Source` and
`V3DestinationFactory: NewV3Destination`. Both `NewV3Source` and `NewV3Destination` in that
file simply call `NewCCIP17EVM` and return the result, since `*CCIP17EVM` already satisfies
both interfaces. A chain family without a single object implementing everything can instead
give each factory a different constructor, e.g. one returning a source-only type and another
a destination-only type.

### 3. Implement optional capabilities as needed

Only implement these if you intend to run the test cases that need them:

| Interface | Needed by | Method(s) |
| --- | --- | --- |
| `TokenBalanceReader` | `token_transfer` suite (source and destination) | `GetTokenBalance` |
| `SenderAddressProvider` | `token_transfer` suite (source) | `GetSenderAddress` |
| `MaxDataSizeProvider` | `basic.MaxDataSize` test case (destination) | `GetMaxDataBytes` |
| `ProgressableChain` | tests that need forced block progression (e.g. anvil-only) | `SupportManualBlockProgress`, `AdvanceBlocks` |
| `ReorgableChain` | reorg-simulation tests | `SupportReorgs`, `Snapshot`, `Revert` |

**Reference:** `*CCIP17EVM`'s implementations of these live in `build/devenv/evm/impl.go`
(`GetSenderAddress`, `GetTokenBalance`, `GetMaxDataBytes`) and
`build/devenv/evm/block_progression.go` (`SupportManualBlockProgress`, `SupportReorgs`, and
the rest of `ProgressableChain`/`ReorgableChain`).

Test cases type-assert these at the point of use and skip (`HavePrerequisites` returns
`false`) or return a clear error if the assertion fails — see `basic/v3.go`'s
`maxDataSize` hydrate closure or `token_transfer/v3.go`'s balance/sender lookups for the
pattern to follow if you're writing a new test case with its own optional capability.

### 4. Run the standard test suite

Once registered, resolve your chain via `ccv.Lib` and run the standard test cases exactly
as any other family does:

```go
v3Src, err := lib.V3Source(ctx, srcSelector)
v3Dst, err := lib.V3Destination(ctx, dstSelector)

for _, tc := range basic.All(lib, srcSelector, dstSelector, basic.Args{}) {
	if !tc.HavePrerequisites(ctx) {
		t.Skip(tc.Name())
	}
	require.NoError(t, tc.Run(ctx), tc.Name())
}
```

Or send a single message directly with `tcapi.SendV3Message(ctx, v3Src, v3Dst, ...)` and
assert on it with `tcapi.NewTestingContext` + `TestingContext.AssertMessage`.

## Interface reference

| Type | Package | Purpose |
| --- | --- | --- |
| `TestCase` | `tcapi` | Standard test case contract (`Name`, `Run`, `HavePrerequisites`) |
| `V3Source` | `cciptestinterfaces` | Minimal capability to originate a V3 message |
| `V3Destination` | `cciptestinterfaces` | Minimal capability to receive a V3 message |
| `TokenBalanceReader` | `cciptestinterfaces` | Optional: report a token balance |
| `SenderAddressProvider` | `cciptestinterfaces` | Optional: report the default sender address |
| `MaxDataSizeProvider` | `cciptestinterfaces` | Optional: report max message data size |
| `ProgressableChain` | `cciptestinterfaces` | Optional: force block progression |
| `ReorgableChain` | `cciptestinterfaces` | Optional: snapshot/revert chain state |
| `chainreg.Registration` | `chainreg` | Per-family registration bundle (factories, resolvers, serializers, ...) |
| `chainreg.V3SourceFactory` / `V3DestinationFactory` | `chainreg` | Constructors registered for partial (V3-only) chain families |
| `ccv.Lib.V3Source` / `V3Destination` | `build/devenv` | Resolves a chain by selector, using the registered factory or falling back to `ChainsMap` |
