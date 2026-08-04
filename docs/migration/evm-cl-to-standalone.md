# Migrating an EVM node operator from CL mode to standalone

A node operator running CCV as jobs on a Chainlink node moves to two standalone processes, a verifier
and an executor, without touching a contract and without a duplicate entry in the Job Distributor.
This document is the procedure. It assumes EVM; other families are standalone from the start and have
nothing to migrate.

The migration is a cutover, not a coexistence period. When it is done the Chainlink node no longer
runs the CCV jobs.

One key carries over and one does not. The verifier's onchain signing key is preserved, because a
contract depends on it. The executor's transmitter is not: the standalone executor runs a single
fresh key that is funded during the cutover, the one funded account a live deployment gives an
operator in place of the node's per-chain transmitters. So no gas is moved, and the operator's old
per-chain accounts are simply left where they are.

## What has to carry over, and why

The **OCR2 EVM key bundle's onchain signing key** is the address in the `CommitteeVerifier` signer
set. The node publishes it to JD as `OnchainSigningAddress`, and `ApplyVerifierConfig` reads it back
from there when it configures the contract. If you generate a new one, the committee's signer set has
to be updated on every chain, which needs a config transaction per chain and coordination with the
other operators in the committee. This is the one key the export carries.

The **executor's transmitter** is not carried over. A Chainlink node transmits from an EVM account
per destination chain; the standalone executor holds a single key instead, funded fresh for this
operator. Nothing on chain names the transmitter, so a new funded account works with no
reconfiguration, and the operator's per-chain balances are untouched by the move.

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
standalone those are two processes with two keystores, so they need two records. The verifier adopts
the operator's existing record, keeping the NOP alias that `ApplyVerifierConfig` and
`fetch_signing_keys` look up by. The executor registers a new one.

That second record is a property of standalone mode, not of the migration: an operator who had
started standalone would have had two from the beginning. What the migration avoids is a *duplicate*
— the operator's existing record is reused for the verifier rather than abandoned next to a new one.

The two processes differ in what they carry across. The verifier imports the node's signing key, so
its identity is preserved. The executor does not import anything: it generates a fresh transmitter
key and is funded for it, one account instead of the node's per-chain transmitters. This is the
single-key executor a live deployment runs, brought up per operator as part of the cutover.

### Check first: how many verifier jobs the node runs

A standalone process runs a single job, so this procedure applies to a node running one
`ccvcommitteeverifier` job.

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

## Who does what

The operator's part is steps 1 through 5: export the signing key, configure and start the standalone
verifier and executor, stop the Chainlink node. Everything after — repointing the verifier's JD
record, registering the executor, funding its transmitter, flipping the topology, proposing the
standalone specs — is on the Chainlink Labs side, because JD and the topology are centrally operated.
Each step below is labeled with who runs it.

That split is also the safety net. Before the standalone specs are proposed, each operator's signing
address is read back from JD and required to be unchanged across the cutover — the same assertion
`TestE2EMigration_CLToStandalone` makes. A mistake in the operator's steps is caught there,
centrally, before any job moves.

## Before you start

Have ready:

- The Chainlink node's API credentials, in a file with the email on line 1 and the password on
  line 2 — the layout `chainlink admin login --file` reads. The export tool uses them, and the
  export endpoints need the node's admin account.
- A Postgres database for each standalone process. The verifier and executor each need their own
  bootstrap database, separate from any application database. Create them empty and hand each process
  a connection string: the schema is created on first boot and left alone on every boot after, so
  there is nothing to migrate by hand.
- The Chainlink node's TOML configuration file.
- The verifier and executor images you are about to deploy. The export tool ships in both as
  `ccv migrate`, so there
  is nothing separate to install.

## Step 1: export the signing key (node operator)

Run the export tool from the verifier image. It finds the OCR2 bundle registered for EVM — the same
source the node's JD chain config was built from, so nothing is transcribed and nothing is guessed —
exports it under a generated password, and verifies the file decodes to the identity the node
registered, while the node is still up to correct a mistake:

```sh
docker run --rm --network host -v "$PWD/migration:/out" <verifier-image> \
  ccv migrate export \
    --node-url http://localhost:6688 \
    --api-creds /out/api-creds.txt \
    --out-dir /out
```

`--network host` lets the container reach a node API on the host's `localhost`; if the node's API
is reachable at another address, point `--node-url` at it instead. The credentials file sits in the
mounted directory so the container can read it.

The tool runs the job-count check from the previous section itself and stops with an error on a
node running more than one verifier job, rather than picking one. It also stops if the node has
several EVM OCR2 bundles; in that case take the right one from the JD node record — never from a
guess — and pass it as `--bundle-id`.

What it writes into the output directory:

- `ocr2.json` — the export, mode 0600.
- `export-password.txt` — the generated password, mode 0600.
- `verifier.key_import.toml` — the `[key_import]` block for the verifier, with `expected_id` already
  filled in from the export. Do not retype the address.

The manual equivalent — `chainlink keys ocr2 list` and `export` — still works if the tool cannot
reach the node. If you use it, take the address for `expected_id` from the JD node record, not from
the list output you happened to pick: the whole point of the check is that it disagrees with a wrong
choice.

## Step 2: reuse the node's RPC configuration (node operator)

There is nothing to convert. Mount the Chainlink node's own TOML config file at the verifier's EVM
config path and it is read directly: the `[[EVM]]` and `[[EVM.Nodes]]` sections are translated at
startup, chain IDs are resolved to chain selectors, and every other section in the file is ignored.

Finality carries over as the node had it. The node's own chain defaults are applied before
translating, so a chain you never configured explicitly keeps the behavior it had rather than
quietly moving onto finality tags.

A few things a Chainlink node can express have no standalone equivalent and are dropped: send-only
nodes, and per-node `Order`, `HTTPURLExtraWrite` and `IsLoadBalancedRPC`. Each one is logged at
startup saying exactly what was dropped. If you rely on a send-only endpoint, add it as a full node.

## Step 3: configure the standalone verifier to adopt the key (node operator)

Step 1 wrote the block the verifier needs. Mount `ocr2.json` and the password file into the
verifier's container at the paths the snippet names — renaming the key file to `key.json` on the
way in — and add the snippet's `[key_import]` block to the bootstrap config:

```toml
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "0x..."
```

Two paths and one check. You do not say which keystore key the file becomes, because the verifier
has exactly one it can import into, and you do not say which export it is, because that is read from
the file.

`expected_id` is the signing address from step 1, written into the snippet by the tool. It is
required — the bootstrapper refuses to start without it — because it is the check that fails the boot
when the wrong node's export is mounted: without it the process comes up signing with another
operator's key, which produces verification results the committee rejects with nothing in the logs
pointing at the cause. The tool already wrote it, so paste the block as generated and do not retype
the address.

Before starting the verifier, you can confirm the mounted file reads back as the right identity
without booting anything:

```sh
ccv migrate inspect \
  --key-file /etc/ccv/migration/key.json \
  --password-file /etc/ccv/migration/export-password.txt
```

The import runs only when the key is absent, so it is a no-op on every restart after the first. Once
the verifier has come up once, unmount the export and the password file and delete them.

The executor needs no `[key_import]`. It generates its own transmitter key on first boot, which
Chainlink Labs funds in step 6; give it its bootstrap config and the same mounted node TOML from
step 2, and nothing else.

## Step 4: stop the Chainlink node (node operator)

Stop it before starting the standalone verifier. The verifier is about to take over its JD record,
and while the node is connected the two contend for it.

The hard deadline is the repoint in step 6: the node has to be down before its JD record changes
hands, which is before any standalone job is sent. Stopping it here, before the standalone processes
start, is what keeps the window where no one serves the lane short and removes any doubt about
which process owns the record.

Stopping the node ends CL mode for this operator. Both CCV jobs ran on the one node, so it cannot
serve one of them while the other migrates; the standalone verifier and executor take over the lane
once they are up.

## Step 5: start the standalone processes (node operator)

Start the verifier and the executor. The verifier generates its own CSA key on first boot and imports
the signing key you declared; the executor generates its own CSA and transmitter keys, funded in the
next step. Read the verifier's CSA public key from its info server:

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

## Step 6: hand the JD record to the verifier, register and fund the executor (Chainlink Labs)

Repoint the operator's existing JD node record at the verifier's CSA public key, keeping the node ID
and the NOP alias. Register the executor as a new node under its own name and CSA key, and fund the
transmitter address it generated so it can pay for execution.

Wait for JD to report both as connected before proposing jobs. A proposal sent to a record whose new
owner has not dialed in yet sits unclaimed.

## Step 7: propose the standalone job specs (Chainlink Labs)

Set the operator's mode to `standalone` in the topology and re-run `ApplyVerifierConfig` and
`ApplyExecutorConfig`. The two modes differ in one field: a CL-mode spec carries the app config under
`committeeVerifierConfig` and `executorConfig`, a standalone spec under `appConfig`. Proposing the
standalone specs replaces the CL-mode ones, and the previous proposals are revoked.

Because the signing address did not change, the verifier changeset produces no contract transaction.
If it proposes one, the imported key is not the one the committee has registered; stop and re-check
step 1.

## Step 8: confirm and clean up (both)

Send a message across a lane this operator verifies and confirm it is verified and executed. Then
confirm on chain that the committee's signer set for this operator is unchanged. The executor's
transmitter is a new funded account by design, so it is expected to differ from the node's.

Finally, remove the CCV job specs from the Chainlink node and the exported key files from wherever
you staged them.

## If it goes wrong

Up to step 4 nothing has changed: the Chainlink node is still running its jobs, and the standalone
processes are not registered anywhere. Delete the export and stop.

After step 4 the way back is to restart the Chainlink node, repoint the JD record at its CSA public
key, and re-propose the CL-mode specs. The key the standalone verifier imported is a copy, so the
node's own keystore is untouched and it can resume signing and transmitting as before. The executor's
own JD record and fresh key are discarded. Do this only with the standalone verifier stopped, for the
same reason step 4 exists.

One trap has no clean undo and is easier to avoid than to hit: a verifier that came up once
*without* `[key_import]` has already generated its own signing key, and the import is a no-op while a
key with that name exists. Adding `[key_import]` afterwards does not fix it — `expected_id` is
checked against the key already in the keystore, so the process now refuses to start because the
generated key is not the pinned one. If nothing has registered with JD yet, the fix is to delete the
verifier's bootstrap database and let it recreate the schema, and the import, on the next start. If
registrations already happened, sort the keystore out with Chainlink Labs rather than deleting your
way deeper.

## What is not covered

An operator whose signing key is in an HSM or KMS cannot export it, so this procedure does not apply.
That case needs a new signing key and a committee signer-set update on every chain. Plan it with the
committee rather than as a unilateral migration.

The node's old per-chain transmitter accounts are not migrated or drained. A Chainlink node transmits
from an EVM account per destination chain; the standalone executor replaces all of them with the one
fresh key it is funded for. The balances on the old accounts are left where they are — nothing in
this procedure moves them, so recovering that gas, if it is worth recovering, is a separate manual
step the operator does on their own schedule.
