# Human Overview

Importing `integration/pkg/accessors/evm` no longer registers the EVM accessor factory and
declared-chain coverage checker with `chainaccess`. That side effect moved to the new package
`integration/pkg/accessors/evm/register`, which exists only to be blank-imported by binaries that
select the standalone EVM driver:

```go
_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/register"
```

This is a prerequisite for the multi-client verifier: a plugin-based factory (`evm/plugin`) must be
able to register in place of the standalone factory, and the global registry panics on duplicate
registration, so both registrations cannot live behind the same import.

`integration/pkg/constructors` deliberately does **not** import `evm/register`: it is a wiring
library, and registration is a binary-level choice. Keeping the import there would force every
consumer onto the standalone factory and panic the moment one registers a plugin factory instead.

# Adopting the change

* The standalone binaries in this repo (`cmd/verifier/committee`, `cmd/verifier/token`,
  `cmd/executor/standalone`) already import `evm/register` — no action needed here.
* External consumers that previously relied on the transitive side effect — the Chainlink node repo,
  which embeds the committee verifier via `integration/pkg/constructors` — must add the blank import
  above to the binary that embeds the verifier. Without it, jobs on EVM chains fail at startup with
  "no accessor factory registered for family evm".
* Code that imports the `evm` package only for its types or constructors
  (`evm.CreateEVMAccessorFactory`, config types) needs no change; that import is now side-effect
  free.
