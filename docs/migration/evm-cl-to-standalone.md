# Migrating an EVM node operator from CL mode to standalone

Your CCV jobs move off your Chainlink node and onto two standalone processes, a verifier and an
executor. Your signing key comes with you, so nothing changes on chain.

Node operators do steps 1 to 7. Chainlink Labs does steps 8 to 10, coordinating one additional
operator action in step 9 if a chain is disabled. The appendix explains what is happening and why,
if you want it — you do not need it to run the steps.

---

# Part 1: node operator steps

## Before you start

**Stop and contact Chainlink Labs first if** your signing key is in an HSM or KMS. It cannot be
exported, so this procedure does not apply to you.

You need:

- Your Chainlink node's API credentials in a file: email on line 1, password on line 2.
- Your Chainlink node's TOML config file.
- Three empty Postgres databases: one bootstrap database for each process, plus the verifier's
  application database. They may share a server, but must be different database names.
- A bootstrap secrets file for each process and an application secrets file for the verifier, as
  described in step 3.
- The verifier and executor images.

Fill these in once and reuse them in the commands below:

| Placeholder            | What it is                                          |
|------------------------|-----------------------------------------------------|
| `<verifier-image>`     | The verifier image you are deploying                |
| `<executor-container>` | Your executor's container name                      |
| `<node-url>`           | Your Chainlink node's API URL, e.g. `http://localhost:6688` |

## Step 1: check your node's jobs and chain statuses

```sh
chainlink jobs list
chainlink node ccv chain-statuses list
```

**Check:** exactly one `ccvcommitteeverifier` job. If you see more than one, stop and contact
Chainlink Labs — do not continue.

You will also see a `ccvexecutor` job. That is expected: CCIP 2.0 runs two job specs on your node, one
per component.

Check the `disabled` column in the chain-status output. Normally every row is `false`. If any row is
`true`, record its chain selector and tell Chainlink Labs; do not enable it. You must restore the
disabled state after the standalone job first starts in step 9 before the cutover can be confirmed.

## Step 2: export the signing key

Put your API credentials file at `./migration/api-creds.txt`, then run:

```sh
docker run --rm --network host -v "$PWD/migration:/out" <verifier-image> \
  ccv migrate export \
    --node-url <node-url> \
    --api-creds /out/api-creds.txt \
    --out-dir /out
```

This writes three files into `./migration/`:

- `ocr2.json` — your key.
- `export-password.txt` — its password.
- `verifier.key_import.toml` — a config snippet to paste in step 3.

**Check:** the command printed a signing address, and all three files exist. If the command errors,
read the error and stop — it is telling you something is wrong with the node or the flags.

## Step 3: configure the verifier and executor

Do all six:

1. Mount your Chainlink node's TOML config file into **both** containers as their EVM config. Do not
   edit it.
2. Mount a different bootstrap secrets file into each process. Its default path is
   `/etc/bootstrap/secrets.toml`; `BOOTSTRAPPER_SECRETS_PATH` overrides the path. Each file contains
   that process's bootstrap `[db].url` and `[keystore].password`.
3. Mount the verifier application secrets at `/etc/committee-verifier/secrets.toml`;
   `COMMITTEE_VERIFIER_SECRETS_PATH` overrides the path. Its `[db].url` points to the third database,
   not the verifier bootstrap database, and its `[[aggregators]]` entries hold the HMAC credentials.
4. Mount `ocr2.json` into the **verifier** at `/etc/ccv/migration/key.json` (note the rename).
5. Mount `export-password.txt` into the **verifier** at
   `/etc/ccv/migration/export-password.txt`.
6. Copy the `[key_import]` block out of `verifier.key_import.toml` and paste it into the verifier's
   bootstrap config. It looks like this, with your address already filled in:

```toml
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "0x..."
```

Do not retype the address. Do not add `[key_import]` to the executor.

The complete schemas are in the [bootstrap secrets reference](../config/bootstrap/secrets.documented.toml)
and [verifier secrets reference](../config/verifier/secrets.documented.toml). For backwards
compatibility, the verifier application DB URL can instead come from `CL_DATABASE_URL`, and HMAC
credentials can come from `VERIFIER_AGGREGATOR_*_API_KEY` and
`VERIFIER_AGGREGATOR_*_SECRET_KEY`; the secrets file wins when both are present.

Confirm the mounted file is the right one:

```sh
ccv migrate inspect \
  --key-file /etc/ccv/migration/key.json \
  --password-file /etc/ccv/migration/export-password.txt
```

**Check:** the address it prints matches `expected_id` in the block you pasted.

## Step 4: stop the Chainlink node

Stop it now, before starting anything else. Pick a quiet moment if you can.

**Check:** the node's API no longer answers.

## Step 5: start the verifier and executor

Start both.

**Check:** both are running and healthy, neither is restarting, and the verifier's log does not
mention an `expected_id` mismatch. Healthy means the process's own `/health` endpoint answers 200 —
see [Health and readiness endpoints](#health-and-readiness-endpoints). If the verifier refuses to
start, do not work around it — go to [If something goes wrong](#if-something-goes-wrong). The
`signer_address` check runs when the job starts in step 9.

## Step 6: send Chainlink Labs two keys

Run this against the verifier, then against the executor. Port `9988` is whatever you set as
`listen_port` in the `[server]` section:

```sh
curl -s -X POST localhost:9988/keystore/reader/getkeys \
  -d '{"KeyNames":["bootstrap_default_csa_key"]}'
```

Send Chainlink Labs the `PublicKey` value from each, and say which one is the verifier and which is
the executor. Copy the values exactly as they appear.

This is the same CSA key hand-off you did when you first onboarded, when you sent us the key from your
node's `v2/keys/csa`. The difference is that there are now two processes with their own keys instead of
one node.

**Never send anyone:** a private key, `ocr2.json`, `export-password.txt`, or your API credentials.
Nothing in this procedure needs them. If someone asks you for one, they are not following this
procedure.

**Check:** you sent two values and labelled which process each came from.

## Step 7: fund the executor

Get the executor's address:

```sh
docker logs <executor-container> | grep evm/tx/executor_evm_transmitter_key
```

Copy the `evmAddress` value from that line. Send gas to it on every chain your executor runs on. Your
old per-chain transmitter accounts are where that gas comes from, and they keep whatever you do not
move.

**Check:** the address has a non-zero balance on every chain, confirmed on chain rather than assumed.

Keep a balance alert on that address for every chain afterwards. The standalone executor does not
run the Chainlink node's balance monitor, so an account that later runs dry shows up first as
failed broadcasts, not as an alert. If you already alert on your node's per-chain transmitter
balances, add this address to that alerting; if not, any external balance watcher works.

> This step gets easier: CCIP-12871 adds a command that reads the address and moves the balances for
> you. Until then the sends are manual.

Tell Chainlink Labs when steps 6 and 7 are done. They take it from there.

**You will not be asked to accept a job spec.** On your Chainlink node you accepted the CCIP job spec
in the JD UI. The standalone processes approve their own, so there is nothing waiting for you there and
nothing to click. If you are watching the JD UI for something to accept, you are waiting for something
that will not arrive.

## If something goes wrong

**Before step 4** nothing has changed. Delete the files from step 2 and stop.

**After step 4**, contact Chainlink Labs. Going back means restarting your Chainlink node and having
your JD record pointed back at it, which is not something you can do alone. Your node's own key is
untouched — step 2 exported a copy — so it can pick up where it left off.

**Do not** start the verifier without the `[key_import]` block from step 3, at any point. If it comes
up once without it, it generates its own signing key and adding the block afterwards will not fix it.
If you have already done this, contact Chainlink Labs rather than deleting anything.

---

# Part 2: Chainlink Labs steps

When scheduling several operators, keep at most (committee size − threshold) of them mid-cutover at
once — see [How many operators can migrate at once](#how-many-operators-can-migrate-at-once).

## Step 8: hand over the JD record and register the executor

Using the two CSA public keys from step 6:

1. Repoint the operator's existing JD node record at the verifier's CSA public key. Keep the node ID
   and the NOP alias.
2. Register the executor as a new JD node under its own name and CSA public key.

Wait for JD to report both connected before proposing jobs. A proposal to a record whose new owner
has not dialed in sits unclaimed.

## Step 9: propose the standalone job specs

1. Set the operator's mode to `standalone` in the topology.
2. Re-run `ApplyVerifierConfig` and `ApplyExecutorConfig`.

**`ApplyVerifierConfig` must produce no contract transaction.** If it proposes a signer change, the
key the verifier imported is not the one the committee has registered. Stop and recheck the
operator's step 2.

It will also refuse to propose if the chain is not registered in JD for that operator, which means
the verifier is not reporting its chain configs.

**Check:** the verifier job starts and its log does not report a `signer_address` mismatch. If it
does, stop and return to the operator's key-import checks; do not propose a replacement signer.

If the operator recorded no disabled chain in step 1, continue to step 10. Otherwise, wait for the
standalone verifier job to start and create its application-database rows, then coordinate this gate
with the operator:

1. Run `verifier ccv chain-statuses list` and note the standalone `verifier_id`.
2. Stop the verifier.
3. For every selector recorded in step 1, run:

   ```sh
   verifier ccv chain-statuses disable \
     --chain-selector <selector> \
     --verifier-id <standalone-verifier-id>
   ```

4. Restart the verifier and run `verifier ccv chain-statuses list` again.

**Do not continue to step 10** until every recorded selector shows `disabled = true`. Run these CLI
commands with the same verifier application secrets file so they connect to the correct database.

## Step 10: confirm and clean up

1. Send a message across a lane this operator verifies. Confirm it is verified and executed.
2. Confirm on chain that the committee's signer set for this operator is unchanged.
3. Tell the operator to remove the CCV job specs from their Chainlink node, and to delete
   `ocr2.json` and `export-password.txt`.

---

# Appendix: what is happening

Nothing here is needed to run the steps.

The executor's transaction-manager choice and cutover gates are summarized in the
[TXM v2 assessment](txm-v2-assessment.md).

## Before and after

| Component           | CL mode                                      | Standalone                                          |
|---------------------|----------------------------------------------|-----------------------------------------------------|
| Onchain signing key | OCR2 EVM key bundle on the node              | The same key, imported from the export              |
| Transmitter         | One EVM account per destination chain        | One fresh key the executor generates, funded by the operator |
| CCV jobs            | Two jobs on one node                         | One job on each of two processes                     |
| JD node record      | One record for both jobs                     | Two: verifier adopts the existing one, executor is new |
| CSA key             | The node's                                   | Each process generates its own                       |
| EVM RPC config      | The node's TOML                              | The same file, read directly                         |
| Database            | The node's Postgres                          | One bootstrap database per process, plus the verifier application database |

## Executor timing stays aligned

Standalone keeps CL mode's 2-second NTP retry backoff and 24-hour indexer message-deduplication
window. `source_backoff_duration` controls failed Indexer requests only; changing it does not change
NTP recovery timing.

## Why the signing key carries over

The OCR2 bundle's onchain signing key is the address in the `CommitteeVerifier` signer set. The node
publishes it to JD as `OnchainSigningAddress`, and that is where the changesets read each operator's
signer from. A new key would mean updating the committee's signer set on every chain: a config
transaction per chain, plus coordination with every other operator in the committee. So it is
exported and imported instead.

The standalone verifier keeps publishing it. It declares its chains in the bootstrap config and
reports them to JD on connect, as the node did. For EVM that is required, not optional — both
`ApplyVerifierConfig` and `ApplyExecutorConfig` check the chain is registered in JD before proposing a
job spec. `ApplyVerifierConfig` also persists the alias-to-signer mapping into environment state (the
`nopSigners` index), which is what covers chain families whose standalone verifiers do not report
chain configs to JD at all.

`expected_id` in the `[key_import]` block is what makes a wrong-node mount fail at boot instead of
silently. Without it a process would come up signing with another operator's key, and the committee
would reject its results with nothing in the logs explaining why. That is why it is required and why
the export tool fills it in rather than asking anyone to type an address.

## Why the CSA key does not

The CSA key authenticates a node to JD. It has no on-chain meaning, so it is not exported. The JD
record is repointed at the standalone verifier's own CSA key instead, which keeps the node ID, the
name, and the job history while the key stays on the machine that generated it.

This is the one thing the operator has to hand over, and it cannot be automated away. JD identifies a
node by the key it authenticates with, and a process cannot repoint its own record: it cannot
authenticate as that record until the record already carries its key, and the update it does send on
connect carries chain configs only, never a public key. So the change has to be made on the JD side
first. The alternative — exporting the CSA private key — would copy a private key off the node and,
for as long as both processes held it, leave two processes able to claim one identity.

It is also why the Chainlink node must be stopped before the standalone verifier starts. One record
cannot have two owners.

## Why nothing is accepted in the JD UI

A Chainlink node holds job proposals until a human approves them, which is why onboarding ends with
the operator accepting the CCIP job spec. The standalone bootstrapper's JD lifecycle manager validates
the proposal, starts the job, and calls `ApproveJob` itself, so a standalone process approves its own
specs. Nothing about the migration changes what the specs contain — only who accepts them.

## Why one JD record becomes two

In CL mode one record runs both the `ccvcommitteeverifier` and `ccvexecutor` jobs. Standalone runs two
processes with two keystores, so it needs two records. The verifier adopts the existing record,
keeping the NOP alias the changesets look up by; the executor registers a new one.

Two records is a property of standalone mode, not of the migration — an operator who started
standalone would have had two from the beginning. What the migration avoids is a duplicate: the
existing record is reused rather than abandoned next to a new one.

## Why the executor's transmitter is new

A Chainlink node transmits from one EVM account per destination chain. The standalone executor holds a
single key instead, and generates it itself. Nothing on chain names the transmitter, so a new account
needs no reconfiguration.

JD does learn the address — the bootstrapper publishes the declared secp256k1 key as the signing
address on its own chain configs, and on the executor that key is the transmitter — but the executor
does that itself. Nothing about the transmitter is transcribed or handed over. The only thing the
operator does with it is fund it. That self-publication is also why the executor needs no identity
check comparable to the verifier's `signer_address` guard: the address JD registers is the one the
executor published, and the operator's funding in step 7 confirms it is the intended account.

## Why the node's TOML is reused as-is

The `[[EVM]]` and `[[EVM.Nodes]]` sections are translated at startup and chain IDs resolved to chain
selectors; every other section is ignored. Reusing the file rather than rewriting it is what keeps
finality behavior identical across the cutover — the node's own chain defaults are applied before
translating, so a chain that was never configured explicitly keeps the behavior it had instead of
moving onto finality tags.

Per-node `Order` carries over, so a converted node keeps the RPC prioritization the operator set. A
node with no `Order` stays at the pool's lowest priority, which is how chainlink-evm treats it too.

Chain-level tuning beyond finality — gas estimation, node pool, head tracker, and
transaction-manager settings — does not carry over, with one exception:
`Transactions.TransactionManagerV2.BlockTime`. Whatever the node config sets that the conversion
drops is logged by name at startup, so custom tuning surfaces instead of silently reverting to
chain defaults.

If the node config sets no TXM v2 block time, standalone runs a 2-second block time, which retries
and fee-bumps far more aggressively than the node did on a slow chain. Agree a per-chain value with
Chainlink Labs before the cutover; the [TXM v2 assessment](txm-v2-assessment.md) explains the
fallback.

Send-only nodes and the per-node `HTTPURLExtraWrite` and `IsLoadBalancedRPC` settings have no
standalone equivalent and are dropped. Each one is logged at startup. An operator relying on a
send-only endpoint should add it as a full node.

## Finality checking stays on

The job spec accepts `disable_finality_checkers`, but only standalone mode honors it; CL mode
ignores it and always runs finality checkers. Do not set it on an EVM job: the node never disabled
checking, so the cutover must not either. The field exists for chain families whose standalone
deployments predate this procedure.

## Stopping the node mid-flight

The standalone executor reads each message's on-chain execution state before executing, so anything
the node already landed is skipped. The gap is a transaction the node submitted that has not confirmed
yet: the state read still says unexecuted, so the standalone executor can submit its own attempt from
its own account. One lands and the other reverts — a wasted transaction, not a double delivery. A
drained queue is still cleaner than a raced one.

## Verification, and where it happens

The operator's signing address is read from JD before the cutover, while the Chainlink node still owns
the record, and required to be unchanged afterwards. `TestE2EMigration_CLToStandalone` makes exactly
that assertion. The pre-cutover read has to come first because the record changes hands in step 8, not
because publishing stops.

A mistake in the operator's steps surfaces centrally, before any job moves, in one of two ways: the
verifier changeset wants to change the committee's signer set when it should be a no-op, or it refuses
to propose because the chain is not registered in JD for that operator.

When the job starts, the standalone verifier also compares its keystore address with the job's
`signer_address` and refuses to run on a mismatch. The error points back to `[key_import]` rather than
allowing a wrong key to fail later at aggregator quorum.

The import itself runs only when the key is absent, so it is a no-op on every restart after the first.
Once the verifier has come up once, the export and password files can be unmounted and deleted.

## Health and readiness endpoints

Each standalone process serves two HTTP servers.

The bootstrapper's server listens on `listen_port` from the bootstrap config (9988 in this
procedure). Its endpoints are about the job lifecycle, not component health:

- `/health` is a static 200. It says the process is up and serving, nothing more.
- `/ready` is 503 until the job's Start has returned, then 200; it goes back to 503 while a job is
  stopped or replaced. What it does not cover is a component that fails after Start returned —
  source readers, the coordinator, or the transaction manager can degrade later without `/ready`
  changing.
- `/keystore/reader/getkeys` is the key hand-off endpoint used in step 6.

The application's own server carries the real health signal. By default the verifier listens on
8100 and the executor on 8101; each job's app config can override its own port with
`http_listen_port`. Its `/health` is 200 only when every component in the coordinator's health
report is healthy, and 503 with the failing component named otherwise. The verifier also serves
`/stats` on the same port.

For a Kubernetes deployment: point the liveness probe at the application `/health`, and the
readiness probe at the bootstrapper's `/ready` if you gate rollout on the job having started. Do
not use the bootstrapper's `/health` for either — it cannot fail while the process runs.

## How many operators can migrate at once

The committee keeps verifying as long as `threshold` members are up. From step 4 (node stopped)
until the standalone verifier is confirmed (steps 9 and 10), an operator counts toward neither side,
so the number that can be mid-cutover at once is the committee size minus the threshold — for the
default committee, 16 − 9 = 7.

Derive the number from the committee's live configuration rather than reusing 7: it moves with
committee size and threshold. Because the signing key carries over, a migrated operator counts
toward the threshold again as soon as its standalone verifier is up; the window that consumes
budget is steps 4 to 9.

## Flagged for update

- **CCIP-12871** adds a `ccv migrate` command for step 7: it reads the transmitter address and routes
  the balances from the node's legacy per-chain transmitters into it. Step 7 becomes one command.
- **EVM service state.** The verifier application database already persists chain statuses and
  queues, separately from its bootstrap database. EVM head-tracker and TXM state remain in memory;
  see the [TXM v2 assessment](txm-v2-assessment.md) for the transaction-recovery risk. The known
  delta until then: a restart starts the head tracker cold — it re-syncs from RPC instead of
  resuming from persisted heads the way the node did, which costs catch-up time on restart, not
  correctness.
