# Migrating an EVM node operator from CL mode to standalone

A node operator running CCV as jobs on a Chainlink node moves to the standalone verifier and
executor without touching a contract, without moving funds, and without a second entry in the Job
Distributor. This document is the procedure. It assumes EVM; Solana and Canton were standalone from
the start and have nothing to migrate.

The migration is a cutover, not a coexistence period. When it is done the Chainlink node no longer
runs CCV jobs, and nothing in the deployment refers to CL mode.

## What has to carry over, and why

Three pieces of the Chainlink node's identity are visible outside it.

The **OCR2 EVM key bundle's onchain signing key** is the address in the `CommitteeVerifier` signer
set. The node publishes it to JD as `OnchainSigningAddress`, and `ApplyVerifierConfig` reads it back
from there when it configures the contract. Generate a new one and the committee's signer set has to
be updated on every chain, which needs a config transaction per chain and coordination with the
other operators in the committee.

The **EVM account key** is the transmitter the executor submits from. It is the address JD records
as `AccountAddr`, and it holds the gas the operator funded it with. Generate a new one and the
operator moves funds.

The **CSA key** authenticates the node to JD. It carries no on-chain meaning, so it is not exported.
Instead the JD node record is repointed at the standalone verifier's own CSA key, which preserves
the node ID, its name, and its job history while the key stays on the machine that generated it.
This is also why the Chainlink node must be stopped before the standalone verifier starts: JD
identifies a node by the key it authenticates with, and one record cannot have two owners.

The node's **EVM RPC configuration** carries over too, though nothing outside the node depends on
it. Converting it rather than rewriting it is what keeps finality behavior identical across the
cutover; see step 2.

## One record becomes two

In CL mode a single JD node record runs both the `ccvcommitteeverifier` and `ccvexecutor` jobs. In
standalone those are two processes with two keystores, so they need two records. The verifier
adopts the operator's existing record, keeping the NOP alias that `ApplyVerifierConfig` and
`fetch_signing_keys` look up by. The executor registers a new one.

That second record is a property of standalone mode, not of the migration: an operator who had
started standalone would have had two from the beginning. What the migration avoids is a *duplicate*
— the operator's existing record is reused rather than abandoned next to a new one.

This is the same shape Solana and Canton already run in production, where the committee verifier and
the executor are separate node operator entries with `mode = "standalone"`. EVM is being brought to
the arrangement those families started with, not to a new one.

### Check first: how many verifier jobs the node runs

A standalone process runs a single job, so this procedure applies to a node running one
`ccvcommitteeverifier` job and one `ccvexecutor` job.

```sh
chainlink jobs list
```

If the node runs more than one verifier job, stop and raise it before going further. That happens
when the committee's job specs are still generated per aggregator, which is a property of how
Chainlink Labs runs the aggregators and generates job proposals — nothing a node operator
configures or can change. It has to be resolved on that side first, by consolidating the committee's
verifier jobs into one that writes to every aggregator, and only then does this procedure apply.
Existing credentials survive that change: a consolidated job reuses the per-aggregator `verifier_id`
as each aggregator's credential lookup key, so nothing is re-provisioned.

The cutover stops with an error in that case rather than picking one of the jobs arbitrarily.

## Before you start

Have ready:

- The Chainlink node's API credentials, for the key exports.
- A Postgres database for each standalone process. The verifier and executor each need their own
  bootstrap database, separate from any application database. Create them empty and hand each
  process a connection string: the schema is created on first boot and left alone on every boot
  after, so there is nothing to migrate by hand.
- The Chainlink node's TOML configuration file.
- A password you will encrypt the exported keys under. It is needed once, at first boot.

## Step 1: export the two keys

Find the OCR2 bundle registered for EVM and the account address registered for the chain. These are
the ones the node published to JD, and taking them from anywhere else imports an identity no
contract knows about.

```sh
chainlink keys ocr2 list          # note the ID of the row whose Chain Type is evm
chainlink keys eth list           # note the address for the chain you run
```

Export both under the same password:

```sh
chainlink keys ocr2 export <bundle-id> --newpassword ./export-password.txt --output ./ocr2.json
chainlink keys eth export <address>    --newpassword ./export-password.txt --output ./eth.json
```

Note the two addresses the node prints for these: the OCR2 bundle's onchain signing address and
the account address. Step 3 uses them.

## Step 2: reuse the node's RPC configuration

There is nothing to convert. Mount the Chainlink node's own TOML config file at the standalone
process's EVM config path and it is read directly: the `[[EVM]]` and `[[EVM.Nodes]]` sections are
translated at startup, chain IDs are resolved to chain selectors, and every other section in the
file is ignored.

Finality carries over as the node had it. The node's own chain defaults are applied before
translating, so a chain you never configured explicitly keeps the behavior it had rather than
quietly moving onto finality tags.

Two things a Chainlink node can express have no standalone equivalent and are dropped: send-only
nodes, and per-node `Order` and `HTTPURLExtraWrite`. Each one is logged at startup saying exactly
what was dropped. If you rely on a send-only endpoint, add it as a full node.

## Step 3: configure the standalone processes to adopt the keys

Mount the export and the password file into each container and point at them. The verifier gets
the OCR2 bundle, the executor gets the account key, and the block is the same either way:

```toml
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "0x..."
```

Two paths and one check. You do not say which keystore key the file becomes, because each process
has exactly one it can import into, and you do not say which export it is, because that is read from
the file.

`expected_id` is the address from step 1: the signing address for the verifier, the account address
for the executor. It is optional and safe to skip only if you are migrating exactly one node.
Mounting the wrong node's export otherwise brings up a process that signs with another operator's
key, which produces verification results the committee rejects with nothing in the logs pointing at
the cause. Set it.

The import runs only when the key is absent, so it is a no-op on every restart after the first. Once
each process has come up once, unmount the export and the password file and delete them.

## Step 4: stop the Chainlink node

Stop it before starting the standalone verifier. The verifier is about to take over its JD record,
and while the node is connected the two contend for it.

Stopping the node ends CL mode for this operator. There is no partial state to hold: both jobs run
on the one node, so it cannot serve one of them while the other migrates.

## Step 5: start the standalone processes

Start the verifier and the executor. Each generates its own CSA key on first boot and imports the
key you declared. Read the verifier's CSA public key from its info server:

```sh
curl -s -X POST localhost:9988/keystore/reader/getkeys \
  -d '{"KeyNames":["bootstrap_default_csa_key"]}'
```

The port is the one you set as `listen_port` in the bootstrap config's `[server]` section; 9988 is
the value used throughout this document.

The same endpoint returns the imported signing key, but as a public key rather than an address —
deriving the address from it is a keccak hash of the uncompressed key, not something to do by eye.
Rely on `expected_id` instead: the process refuses to start if the key it imported, or the key
already in its keystore, is not the address you pinned. Reaching a healthy state is the
confirmation.

## Step 6: hand the JD record to the verifier, and register the executor

Repoint the operator's existing JD node record at the verifier's CSA public key, keeping the node ID
and the NOP alias. Register the executor as a new node under its own name and CSA key.

Wait for JD to report both as connected before proposing jobs. A proposal sent to a record whose new
owner has not dialed in yet sits unclaimed.

## Step 7: propose the standalone job specs

Set the operator's mode to `standalone` in the topology and re-run `ApplyVerifierConfig` and
`ApplyExecutorConfig`. The two modes differ in one field: a CL-mode spec carries the app config
under `committeeVerifierConfig` and `executorConfig`, a standalone spec under `appConfig`. Proposing
the standalone specs replaces the CL-mode ones, and the previous proposals are revoked.

Because the signing address did not change, the changeset produces no contract transaction. If it
proposes one, the imported key is not the one the committee has registered; stop and re-check step 1.

## Step 8: confirm and clean up

Send a message across a lane this operator verifies and confirm it is verified and executed. Then
confirm on chain that the committee's signer set for this operator is unchanged and that the
transmitter address the executor submits from is the one the operator funded.

Finally, remove the CCV job specs from the Chainlink node and the exported key files from wherever
you staged them.

## If it goes wrong

Up to step 4 nothing has changed: the Chainlink node is still running its jobs, and the standalone
processes are not registered anywhere. Delete the exports and stop.

After step 4 the way back is to restart the Chainlink node, repoint the JD record at its CSA public
key, and re-propose the CL-mode specs. The keys the standalone processes imported are copies, so the
node's own keystore is untouched and it can resume signing and transmitting as before. Do this only
with the standalone verifier stopped, for the same reason step 4 exists.

## What is not covered

An operator whose keys are in an HSM or KMS cannot export them, so this procedure does not apply.
That case needs a new signing key, a committee signer-set update on every chain, and a new funded
transmitter. Plan it with the committee rather than as a unilateral migration.

An operator whose Chainlink node transmits from a different account per destination chain is not
covered by this version of the procedure, though the shape it needs is supported.

A standalone executor process holds one transmitter key and uses it on every chain it serves, but an
operator is not limited to one executor. Chain scope comes from executor pool membership, so several
executors, each importing a different account and each serving the chains that account is funded on,
is a normal deployment. What is missing is on this side: the cutover exports a single account per
operator and gives every one of their executors the same key, so it cannot yet split them.

The node's JD chain configs settle which case an operator is in. If `AccountAddr` is the same across
them there is one account and this procedure applies as written. If it differs there is one per
chain, and migrating with the current tooling would fund one account on every chain and strand the
balances on the rest. Raise it rather than picking an account.
