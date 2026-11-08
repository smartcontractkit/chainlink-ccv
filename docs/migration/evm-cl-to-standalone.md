# Migrating an EVM node operator from CL mode to standalone

Your CCV jobs move off your Chainlink node and onto two standalone processes, a verifier and an
executor. Your signing key comes with you, so nothing changes on chain.

Node operators do steps 1 to 7, and the cleanup after Chainlink Labs confirms the cutover.
Chainlink Labs does steps 8 to 10, coordinating one additional operator action in step 9 if a chain
is disabled. The appendix explains what is happening and why, if you want it — you do not need it
to run the steps.

---

# Part 1: node operator steps

## Before you start

**Stop and contact Chainlink Labs first if** your signing key is in an HSM or KMS. It cannot be
exported, so this procedure does not apply to you.

You need:

- Your Chainlink node's API credentials in a file: email on line 1, password on line 2.
- Your Chainlink node's TOML config. If the node starts with more than one `-config` file, you need
  all of them; step 3 combines them.
- Three empty Postgres databases: one bootstrap database for each process, plus the verifier's
  application database. They may share a server, but must be different database names. The
  standalone LogPoller reader, if you turn it on later, adds tables to a database of its own or to
  the application database; see [Source logs](#source-logs-rpc-or-a-logpoller). Keep the server's
  data on a persistent volume: from step 5 on, the bootstrap databases hold your keys.
- A bootstrap config and a bootstrap secrets file for each process, and an application secrets file
  for the verifier, as described in step 3.
- The Job Distributor's WebSocket URL and its CSA public key. Chainlink Labs gives you both.
- Your signing address as Chainlink Labs reads it from your JD record. They send it when the
  cutover is scheduled.
- The verifier and executor images.

Run every command from one working directory, outside any git repository. By the end of step 3 it
holds:

| Path              | What it holds                                                          |
|-------------------|------------------------------------------------------------------------|
| `migration/`      | Your API credentials, then the exported key and its password (step 2)  |
| `evm-config.toml` | The copy of your node's TOML config that both processes run on (step 3) |
| `verifier/`       | `config.toml`, `bootstrap-secrets.toml` and `secrets.toml` (step 3)    |
| `executor/`       | `config.toml` and `bootstrap-secrets.toml` (step 3)                    |

Fill these in once and reuse them in the commands below:

| Placeholder            | What it is                                                  |
|------------------------|-------------------------------------------------------------|
| `<verifier-image>`     | The verifier image you are deploying                        |
| `<executor-image>`     | The executor image you are deploying                        |
| `<node-container>`     | Your Chainlink node's container name                        |
| `<node-url>`           | Your Chainlink node's API URL, e.g. `http://localhost:6688` |
| `<node-database-url>`  | The `[Database] URL` in your node's secrets TOML            |
| `<jd-signing-address>` | Your signing address from Chainlink Labs                    |
| `<jd-wsrpc-url>`       | The Job Distributor's WebSocket URL from Chainlink Labs     |
| `<jd-csa-public-key>`  | The Job Distributor's CSA public key from Chainlink Labs    |

The commands assume Docker on a Linux host and name the new containers `ccv-verifier` and
`ccv-executor`. If you run them some other way, translate the commands; the mounts, ports and
checks stay the same.

If an AI agent runs these steps for you, supervise it; this procedure is not meant to run
unattended. Fill in passwords and credentials yourself, and do not let the agent read
`migration/api-creds.txt`, `migration/export-password.txt` or any secrets file; whatever it reads
ends up in its transcript. The agent must stop at every **Approval** point and wait for your
go-ahead: before it sends funds, stops the node, or starts the verifier.

## Step 1: check your node's jobs and chain statuses

```sh
chainlink jobs list
psql "<node-database-url>" -X -c \
  "SELECT chain_selector, verifier_id, finalized_block_height, disabled FROM ccv_chain_statuses ORDER BY 1, 2"
```

`chainlink jobs list` needs a logged-in CLI session. With the node in Docker, run
`docker exec -it <node-container> chainlink admin login` once, then
`docker exec <node-container> chainlink jobs list`. If the host has no `psql`, run it inside your
Postgres container with `docker exec`. Read the table with `psql` rather than
`chainlink node ccv chain-statuses list`: that command opens the node's database itself, waits on
the lease the running node holds, and hangs.

**Check:** exactly one `ccvcommitteeverifier` job. If you see more than one, stop and contact
Chainlink Labs — do not continue.

You will also see a `ccvexecutor` job. That is expected: CCIP 2.0 runs two job specs on your node, one
per component. If you see any other job, tell Chainlink Labs before you continue: stopping the node
in step 4 stops it too.

Check the `disabled` column in the query output. Normally every row is `false`. If any row is
`true`, record its chain selector and tell Chainlink Labs; do not enable it. You must restore the
disabled state after the standalone job first starts in step 9 before the cutover can be confirmed.

## Step 2: export the signing key

Create `./migration/`, put your API credentials file at `./migration/api-creds.txt`, then run:

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" -v "$PWD/migration:/out" <verifier-image> \
  ccv migrate export \
    --node-url <node-url> \
    --api-creds /out/api-creds.txt \
    --out-dir /out \
    --expected-id <jd-signing-address>
```

The image runs as UID 65532, which cannot write into a directory you own, so the command runs as your
own user. `--network host` works on Linux only; on Docker Desktop, drop it and point `--node-url` at
`host.docker.internal`.

`<jd-signing-address>` is your signing address as Chainlink Labs reads it from your JD record
(`OnchainSigningAddress`); they send it to you when the cutover is scheduled. The export fails if
the exported key does not carry exactly that address — the decode check alone cannot catch picking
the wrong OCR2 bundle, because any bundle decodes to a self-consistent identity. If it fails, stop
and tell Chainlink Labs; do not retry with a different value. When that check fails, the export
deletes the key and password it wrote, so there is nothing left in `./migration/` to mount by
accident.

If your node holds more than one EVM OCR2 bundle, the export fails and lists their IDs. Run
`docker exec <node-container> chainlink keys ocr2 list`, find the EVM bundle whose on-chain public
key is `ocr2on_evm_` followed by `<jd-signing-address>` in lowercase without the `0x`, and re-run
the export with `--bundle-id <that ID>`. Keep `--expected-id` as it was; it still rejects any bundle
but the registered one.

This writes three files into `./migration/`:

- `ocr2.json` — your key (mode 0600, owned by you).
- `export-password.txt` — its password (mode 0600, owned by you).
- `verifier.key_import.toml` — a config snippet to paste in step 3.

`ocr2.json` is encrypted, but its password sits next to it in plain text, so anyone who can read
both files can sign as you. Keep `./migration/` out of git and off shared storage.

**Check:** the command printed a signing address that matches `<jd-signing-address>`, and all three
files exist. If the command errors for any other reason, read the error and stop — it is telling
you something is wrong with the node or the flags. Once the check passes, delete
`migration/api-creds.txt`; nothing later needs it.

## Step 3: configure the verifier and executor

Do all seven. Step 5 mounts each file at the path given here.

1. Copy your Chainlink node's TOML config to `evm-config.toml`. Both containers mount the copy as
   their EVM config at `/etc/evm/config.toml` (`EVM_CONFIG_PATH` overrides the path). Leave the
   original alone: a rollback restarts the node on it. If the node starts with several `-config`
   files, concatenate the ones that contain `[[EVM]]` sections into the copy, in the order the node
   loads them. Repeated `[[EVM]]` blocks for one chain merge the way the node merges them, but any
   other table may appear only once, so delete duplicates such as a second `[Feature]`; standalone
   does not read those sections. Change nothing else in the copy, apart from what the settings diff
   below calls for.
2. Write a bootstrap config for each process, `verifier/config.toml` and `executor/config.toml`,
   each mounted at `/etc/config.toml` (`BOOTSTRAPPER_CONFIG_PATH` overrides the path). Start from
   the minimal file below, not from the
   [bootstrap config reference](../config/bootstrap/config.documented.toml): the reference carries
   an example `[key_import]` block, which would end up duplicated in the verifier's file and
   misplaced in the executor's. Each file needs `[jd]` with the Job Distributor's WebSocket URL and
   CSA public key, `[server]` with `listen_port`, and one `[[chains]]` entry (`type = "EVM"` and the
   chain ID) for every EVM chain your node serves, the same list in both files. The two processes
   share the host's network in step 5, so they need different ports: 9988 for the verifier and 9989
   for the executor. `[Monitoring]` is optional; copy it from the reference if you use it.

   ```toml
   [jd]
   server_wsrpc_url      = "<jd-wsrpc-url>"
   server_csa_public_key = "<jd-csa-public-key>"

   [server]
   listen_port = 9988   # 9989 in executor/config.toml

   # One entry per EVM chain your node serves, the same list in both files.
   [[chains]]
   type = "EVM"
   id   = "<chain-id>"
   ```

3. Write a bootstrap secrets file for each process, `verifier/bootstrap-secrets.toml` and
   `executor/bootstrap-secrets.toml`, each mounted at `/etc/bootstrap/secrets.toml`
   (`BOOTSTRAPPER_SECRETS_PATH` overrides the path). Each holds that process's bootstrap `[db].url`
   and its own `[keystore].password`. The keystore password is new and unrelated to the export
   password: generate it with `openssl rand -hex 32` and keep a copy in your password manager. It
   encrypts the keys the process stores in its bootstrap database (the verifier's signing key, the
   executor's funded transmitter key, and their CSA keys), so losing it loses them.
4. Write the verifier application secrets, `verifier/secrets.toml`, mounted at
   `/etc/committee-verifier/secrets.toml` (`COMMITTEE_VERIFIER_SECRETS_PATH` overrides the path).
   Its `[db].url` points to the third database, not the verifier bootstrap database, and its
   `[[aggregators]]` entries hold the HMAC credentials. Each entry's `secret_name` must be the
   verifier ID your node's secrets already use for that aggregator, which is
   `<aggregator name>-<committee>-verifier`, for example `aggregator-1-default-verifier`. The
   consolidated job looks credentials up by those names, so copy each aggregator's key pair under
   its existing ID and do not rename it. In the node's secrets TOML they are the
   `[[CCV.AggregatorSecrets]]` entries: `VerifierID` becomes `secret_name`, `APIKey` becomes
   `api_key`, and `APISecret` becomes `secret_key`. Do not drop `secret_name`; an entry without one
   only serves a committee with a single aggregator.
5. Mount `ocr2.json` into the **verifier** at `/etc/ccv/migration/key.json` (note the rename).
6. Mount `export-password.txt` into the **verifier** at
   `/etc/ccv/migration/export-password.txt`.
7. Copy the `[key_import]` block out of `verifier.key_import.toml` and paste it into
   `verifier/config.toml` from item 2, which must end up with exactly one `[key_import]` block. It
   looks like this, with your address already filled in:

```toml
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "0x..."
```

Do not retype the address. Do not add `[key_import]` to the executor: it would import your signing
key as its transmitter key and send transactions from it.

Both images run as UID 65532, but the files you mount are owned by you, and the exported key, its
password and every secrets file should be mode 0600. UID 65532 cannot read those. Run both
containers as your own user (`--user "$(id -u):$(id -g)"`, as the commands in this procedure do),
or `chown` every mounted 0600 file to 65532. On Kubernetes, set
`runAsUser` to your UID or `chown` to 65532; `fsGroup` alone does not make a 0600 file owned by a
different UID readable.

The complete schemas are in the [bootstrap secrets reference](../config/bootstrap/secrets.documented.toml)
and [verifier secrets reference](../config/verifier/secrets.documented.toml). For backwards
compatibility, the verifier application DB URL can instead come from `CL_DATABASE_URL`, and HMAC
credentials can come from `VERIFIER_AGGREGATOR_*_API_KEY` and
`VERIFIER_AGGREGATOR_*_SECRET_KEY`; the secrets file wins when both are present.

Confirm the export is the right one. The verifier is not running yet, so check it in a one-off
container with the same two mounts:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/migration/ocr2.json:/etc/ccv/migration/key.json:ro" \
  -v "$PWD/migration/export-password.txt:/etc/ccv/migration/export-password.txt:ro" \
  <verifier-image> ccv migrate inspect \
    --key-file /etc/ccv/migration/key.json \
    --password-file /etc/ccv/migration/export-password.txt
```

**Check:** the address it prints matches `expected_id` in the block you pasted.

Then diff the effective chain settings before anything starts, and again after any change to
`evm-config.toml`:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/evm-config.toml:/etc/evm/config.toml:ro" \
  <verifier-image> ccv migrate inspect-config --config /etc/evm/config.toml
```

This runs the same conversion the standalone processes run at startup and prints what each chain
will effectively run: finality, the TXM block time (`txm_block_time_source` says whether the value
came from your config, the chain's curated default, or the generic 2s fallback), head-tracker
persistence, and the RPC node set. `chain_defaults` names the chain defaults those settings
resolve against: chainlink-evm's built-ins with CCIP's overrides, the same pair a Chainlink `ccip`
node image runs with (see [Why the node's TOML is reused as-is](#why-the-nodes-toml-is-reused-as-is)).
Go through the output with Chainlink Labs. Three kinds of finding come out of it, and they are
handled differently:

- `failed_chains` names any chain the conversion skipped whole — an unknown chain ID, a node with
  no HTTPURL, an unservable finality mode — with the reason. Those chains will not be served at
  all. If a chain you serve is listed, fix its `[[EVM]]` section in `evm-config.toml` before
  continuing: the standalone processes refuse to boot when a chain declared in the bootstrap
  `[[chains]]` cannot be served by the mounted config. A leftover chain you no longer serve needs
  nothing, but delete its section from `evm-config.toml` so the startup skip warning stays
  meaningful.
- The `warnings` list names every place standalone will run differently from your node config:
  settings it does not recognize (a setting too new for this release, or a typo of a real one),
  settings it sets itself (the balance monitor, log broadcaster, head persistence, forwarders, and
  dual broadcast; see [Why the node's TOML is reused as-is](#why-the-nodes-toml-is-reused-as-is)),
  settings this release's chainlink-evm rejects, `KeySpecific` entries, and send-only nodes and
  per-node settings beyond the endpoints. `ignored_top_level_sections` names the non-EVM sections
  (`Log`, `WebServer`, `P2P`, `Feature`, …) the conversion does not read at all. If your node sets
  `[Feature] LogPoller = true`, its verifier reads source logs through that LogPoller today and the
  standalone verifier will read them over RPC; see [Source logs](#source-logs-rpc-or-a-logpoller).
  A typo is worth fixing in `evm-config.toml`; the rest is standalone's behavior whatever you
  write. Record that you accept each one, or raise it with Chainlink Labs if a deviation is not
  acceptable.
- Chain-level settings carry over as written, so an agreed change to any of them (the TXM block
  time, the finality pair, gas estimation, the node pool) goes under that chain's `[[EVM]]` block in
  `evm-config.toml` before the containers start, exactly as it would on the node.

This is the pre-cutover settings review, not an optional extra.

## Step 4: stop the Chainlink node

To pay for the executor's gas (step 7) from your old per-chain transmitter accounts, do it now,
while the node can still send from them:

1. Start the executor with its step 5 command. Do not start the verifier yet: it holds your node's
   signing key and takes over its JD record, so it starts only after the node stops. The executor
   is safe to start now, because it gets its own new JD record and no job until step 9.
2. Read its address as in step 7.
3. **Approval:** review each transfer (chain, source account, destination, amount) before it is
   sent. On each chain, send gas to the executor from the node's account for that chain
   (`docker exec <node-container> chainlink keys eth list` shows them). `<amount>` is in
   native-token units, so `0.15` sends 0.15 of the chain's native token; add `--wei` to give it in
   wei.

   ```sh
   docker exec <node-container> chainlink txs evm create \
     --id <chain-id> <amount> <old-account> <executor-address>
   ```

4. Wait for every transfer to confirm. The command only queues the transfer in the node, which
   broadcasts it and bumps its gas until it lands. A transfer still pending when the node stops may
   never land, and those accounts cannot send again.

   **Check:** the executor's balance on every chain shows what you sent, confirmed on chain rather
   than assumed.

**Approval:** stop the node only after the step 3 checks pass and every transfer you made here has
confirmed. Pick a quiet moment if you can. Then stop it, and make sure nothing starts it again: a
node that comes back up runs its CCV jobs on the signing key the verifier is about to hold, and
until step 8 it still owns your JD record.

```sh
docker stop <node-container>
docker update --restart=no <node-container>   # a reboot or Docker restart leaves it stopped
```

If a systemd unit runs the node, use `systemctl disable --now <unit>` instead. It stops the node and
keeps it from starting at boot, where a unit that restarts its container would undo a plain
`docker stop`. If the node is a Docker Compose service, run `docker compose stop <service>` and
remove the service from the compose file, since `docker compose up` starts every service in it.

**Check:** the node's API no longer answers, and nothing is set to start it again.

## Step 5: start the verifier and executor

Start both. Skip the executor command if you started it in step 4.

**Approval:** start the verifier only once the node is stopped and `verifier/config.toml` holds
exactly one `[key_import]` block, carrying `<jd-signing-address>`. A verifier that boots without it
generates its own signing key, and that cannot be undone.

```sh
docker run -d --name ccv-verifier --restart unless-stopped --network host \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/evm-config.toml:/etc/evm/config.toml:ro" \
  -v "$PWD/verifier/config.toml:/etc/config.toml:ro" \
  -v "$PWD/verifier/bootstrap-secrets.toml:/etc/bootstrap/secrets.toml:ro" \
  -v "$PWD/verifier/secrets.toml:/etc/committee-verifier/secrets.toml:ro" \
  -v "$PWD/migration/ocr2.json:/etc/ccv/migration/key.json:ro" \
  -v "$PWD/migration/export-password.txt:/etc/ccv/migration/export-password.txt:ro" \
  <verifier-image>

docker run -d --name ccv-executor --restart unless-stopped --network host \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/evm-config.toml:/etc/evm/config.toml:ro" \
  -v "$PWD/executor/config.toml:/etc/config.toml:ro" \
  -v "$PWD/executor/bootstrap-secrets.toml:/etc/bootstrap/secrets.toml:ro" \
  <executor-image>
```

Host networking lets the RPC URLs in `evm-config.toml` and the hosts in your `[db].url` values
resolve the way they did for the node. If the node reached them by container name on a Docker
network, run both containers on that network (`--network <name>`) and publish the ports you need
with `-p`: 9988 and 9989 now, and 8100 and 8101 once the jobs run.

**Check:**

- `curl -s localhost:9988/health` (verifier) and `curl -s localhost:9989/health` (executor) both
  print `{"status":"ok"}`. This is the bootstrapper's server on `listen_port`. It starts only after
  the keystore is set up, key import included. The application ports (8100 and 8101) stay closed
  until the job arrives in step 9, so do not probe them yet; see
  [Health and readiness endpoints](#health-and-readiness-endpoints).
- The verifier holds your signing key: the address this prints matches `<jd-signing-address>`
  (compare ignoring case).

  ```sh
  curl -s -X POST localhost:9988/keystore/reader/getaddresses \
    -d '{"KeyNames":["bootstrap_default_ecdsa_signing_key"]}'
  ```

- Neither container is restarting (`docker ps`), and `docker logs ccv-verifier 2>&1` does not
  mention an `expected_id` mismatch.

Both processes log failed connections to the Job Distributor until Chainlink Labs finishes step 8.
That is expected: JD does not know their new CSA keys yet.

A process that refuses to boot with `declares EVM chains the mounted EVM config cannot serve` is
telling you the bootstrap `[[chains]]` list and the mounted node config disagree — the error names
the chain and the reason; fix the mount or the declaration rather than working around it. If the
verifier refuses to start, do not work around it — go to
[If something goes wrong](#if-something-goes-wrong). The `signer_address` check runs when the job
starts in step 9.

Then back up both bootstrap databases. They now hold the verifier's signing key, the executor's
transmitter key and both CSA keys, encrypted under the keystore passwords from step 3. Once the
export is deleted and the node is decommissioned, the verifier's bootstrap database is the only
copy of your signing key.

```sh
pg_dump "<verifier-bootstrap-db-url>" -Fc -f verifier-bootstrap.dump
pg_dump "<executor-bootstrap-db-url>" -Fc -f executor-bootstrap.dump
```

The two URLs are the `[db].url` values in `verifier/bootstrap-secrets.toml` and
`executor/bootstrap-secrets.toml`. If the host has no `pg_dump`, run it inside your Postgres
container with `docker exec` and redirect its output to the file. Store the dumps off this host,
and not alongside the keystore passwords.

## Step 6: send Chainlink Labs two keys

Read each process's CSA public key from its `listen_port` (9988 for the verifier and 9989 for the
executor in this procedure):

```sh
curl -s -X POST localhost:9988/keystore/reader/getkeys \
  -d '{"KeyNames":["bootstrap_default_csa_key"]}'   # verifier
curl -s -X POST localhost:9989/keystore/reader/getkeys \
  -d '{"KeyNames":["bootstrap_default_csa_key"]}'   # executor
```

Send Chainlink Labs the `PublicKey` value from each, and say which one is the verifier and which is
the executor. Copy the values exactly as they appear. They are base64; Chainlink Labs converts them.

This is the same CSA key hand-off you did when you first onboarded, when you sent us the key from your
node's `v2/keys/csa`. The difference is that there are now two processes with their own keys instead of
one node.

**Never send anyone:** a private key, `ocr2.json`, `export-password.txt`, a keystore password, a
bootstrap database dump, or your API credentials. Nothing in this procedure needs them. If someone
asks you for one, they are not following this procedure.

**Check:** you sent two values and labelled which process each came from.

## Step 7: fund the executor

Get the executor's address:

```sh
curl -s -X POST localhost:9989/keystore/reader/getaddresses \
  -d '{"KeyNames":["evm/tx/executor_evm_transmitter_key"]}'
```

Send gas to that address on every chain your executor runs on, unless you already did in step 4.
Your old per-chain transmitter accounts are inside the stopped node and can no longer send, so use
any wallet you control. They keep whatever you did not move in step 4.

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

## After Chainlink Labs confirms the cutover

Chainlink Labs tells you when step 10 is done. Then:

1. Recreate the verifier without the export: run `docker stop ccv-verifier && docker rm ccv-verifier`,
   then the step 5 verifier command without its two `/etc/ccv/migration` mounts. Keep the `[key_import]` block in
   `verifier/config.toml`. The key is already stored, so the import is skipped and the files are
   never read, but `expected_id` is still checked on every boot. If the bootstrap database is ever
   lost, the block also makes the verifier refuse to start instead of generating a new signing key.

   **Check:** `curl -s localhost:9988/health` prints `{"status":"ok"}`, and
   `docker logs ccv-verifier 2>&1 | grep 'key already exists, skipping import'` finds the line.
2. Delete `./migration/`.
3. Leave the Chainlink node stopped. Do not start it to delete its CCV job specs: the jobs start
   with it, on the signing key the verifier now holds. Its database still holds the original
   signing key, so keep the database until your step 5 backups are stored; after that you can
   decommission the node.

## If something goes wrong

**Before you stop the node in step 4**, your node and its JD record are as they were. Remove the
executor container if you started it, delete `./migration/`, and stop. If you already sent gas to
the executor, keep its bootstrap database and keystore password: they hold the only key to that
address.

**After you stop the node**, contact Chainlink Labs. Going back means restarting your Chainlink
node and having your JD record pointed back at it, which is not something you can do alone. Your
node's own key is untouched — step 2 exported a copy — so it can pick up where it left off. Before
the node starts, stop both standalone containers (`docker stop ccv-verifier ccv-executor`). From
step 9 on each has a job, which it restarts on its own whenever it boots, so either would otherwise
run next to the node's. Keep their bootstrap databases; the executor's holds the key to the gas you
sent it. Then undo what you did in step 4 to keep the node stopped.

**Do not** start the verifier without the `[key_import]` block from step 3, at any point. If it comes
up once without it, it generates its own signing key and adding the block afterwards will not fix it.
If you have already done this, contact Chainlink Labs rather than deleting anything.

---

# Part 2: Chainlink Labs steps

When scheduling several operators, keep at most (committee size − threshold) of them mid-cutover at
once — see [How many operators can migrate at once](#how-many-operators-can-migrate-at-once).

## Step 8: hand over the JD record and register the executor

Use the two CSA public keys from step 6. The operator sends them as base64 and JD takes hex, so
convert each first with `echo '<PublicKey>' | base64 -d | xxd -p -c 32`.

1. Repoint the operator's existing JD node record at the verifier's CSA public key. Keep the node ID
   and the NOP alias.
2. Register the executor as a new JD node under its own name and CSA public key, with a label
   that matches it alone (for example `target=<executor name>`). Step 9 proposes its job by that
   label.

Wait for JD to report both connected before proposing jobs. A proposal to a record whose new owner
has not dialed in sits unclaimed.

## Step 9: propose the standalone job specs

1. Set the operator's mode to `standalone` in the topology.
2. Propose the verifier job: re-run `ApplyVerifierConfig` for this operator only (`targetNops`),
   with `consolidateAggregators: true` when the committee has more than one aggregator. The flag is
   read per run. Without it the changeset emits one job per aggregator, and a standalone verifier
   keeps only the last job it receives, so it would write to one aggregator.
3. Propose the executor job: take the operator's current executor job spec from the datastore,
   change its envelope field from `executorConfig` to `appConfig`, and propose it with
   `jd_propose_job` to the label from step 8. Keep the name, `externalJobID`, and config, so the
   executor keeps its `executor_id` and its place in the pool. Do not use `ApplyExecutorConfig` for
   a migrated operator: it proposes by NOP alias, and that alias's record now belongs to the
   verifier, which rejects the executor job.

**Check the verifier job's `signer_address` against the address read for step 2.**
`ApplyVerifierConfig` touches no onchain state and never proposes a signer change. It reads the
signer from what the verifier published to JD and writes it into the job, so that field is where a
wrong import would show. If it differs, stop and recheck the operator's step 2.

`ApplyVerifierConfig` also refuses to propose if the chain is not registered in JD for that
operator, which means the verifier is not reporting its chain configs.

**Check:** the verifier job starts and its log does not report a `signer_address` mismatch. If it
does, stop and return to the operator's key-import checks; do not propose a replacement signer.

If the operator recorded no disabled chain in step 1, continue to step 10. Otherwise, wait for the
standalone verifier job to start and create its application-database rows, then coordinate this gate
with the operator:

1. List the chain statuses and note the standalone `verifier_id`:

   ```sh
   docker run --rm --network host --user "$(id -u):$(id -g)" \
     -v "$PWD/verifier/secrets.toml:/etc/committee-verifier/secrets.toml:ro" \
     <verifier-image> ccv chain-statuses list
   ```

2. Stop the verifier: `docker stop ccv-verifier`.
3. For every selector recorded in step 1, run:

   ```sh
   docker run --rm --network host --user "$(id -u):$(id -g)" \
     -v "$PWD/verifier/secrets.toml:/etc/committee-verifier/secrets.toml:ro" \
     <verifier-image> ccv chain-statuses disable \
       --chain-selector <selector> \
       --verifier-id <standalone-verifier-id>
   ```

4. Start the verifier (`docker start ccv-verifier`) and list the chain statuses again.

**Do not continue to step 10** until every recorded selector shows `disabled = true`. The one-off
containers read the verifier application secrets file, so they connect to the same database as the
verifier. Start their arguments at `ccv`: the image's entrypoint is already the verifier binary, and
`docker run <verifier-image> verifier ccv ...` boots a second verifier instead of running the CLI.
Outside Docker, the same commands are `verifier ccv chain-statuses ...`.

## Step 10: confirm and clean up

1. Send a message across a lane this operator verifies. Confirm it is verified and executed.
2. Confirm the operator's executor is landing transactions: its transmitter's nonce moves on at
   least one destination chain. The test message alone does not show this, since any executor in
   the pool can land it.
3. Tell the operator the cutover is confirmed, so they can finish
   [After Chainlink Labs confirms the cutover](#after-chainlink-labs-confirms-the-cutover): unmount
   and delete the export, and leave the node stopped. Do not ask them to start the node to remove
   its CCV job specs; its jobs would start with it, on the signing key the standalone verifier now
   holds.

---

# Appendix: what is happening

Nothing here is needed to run the steps.

The executor's transaction-manager choice and cutover gates are summarized in the
[TXM v2 assessment](txm-v2-assessment.md).

## Before and after

| Component           | CL mode                                      | Standalone                                          |
|---------------------|----------------------------------------------|-----------------------------------------------------|
| Onchain signing key | OCR2 EVM key bundle on the node              | The same key, imported from the export into the verifier's bootstrap database |
| Transmitter         | One EVM account per destination chain        | One fresh key the executor generates, funded by the operator |
| CCV jobs            | Two jobs on one node                         | One job on each of two processes                     |
| JD node record      | One record for both jobs                     | Two: verifier adopts the existing one, executor is new |
| CSA key             | The node's                                   | Each process generates its own                       |
| EVM RPC config      | The node's TOML                              | The same file, read directly                         |
| Database            | The node's Postgres                          | One bootstrap database per process, plus the verifier application database |
| Source events       | `eth_getLogs` per poll, or the node's LogPoller when the node runs one | `eth_getLogs` per poll by default; the verifier's own LogPoller is opt-in per chain (see [Source logs](#source-logs-rpc-or-a-logpoller)) |

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
selectors; every other section is ignored, and named both at startup and in the report's
`ignored_top_level_sections`. Reusing the file rather than rewriting it is what keeps each chain's
behavior identical across the cutover: the chain-level settings (gas estimation, node pool, head
tracker, finality, chain type, RPC error patterns) carry over as written, over the same chain
defaults the node ran with.

Those defaults come in two layers, both embedded in the verifier and executor: chainlink-evm's
built-in defaults, and CCIP's overrides of them (`ccip/config/evm` in the chainlink repo). That is
the pair a Chainlink `ccip` node image runs with, through `CL_CHAIN_DEFAULTS=/ccip-config`. A node
on the core image with that variable empty runs chainlink-evm's built-ins alone and differs on
settings its config does not pin, such as an 8,000,000 versus 500,000 gas limit cap. Standalone
always resolves the CCIP pair, so a chain that was never configured explicitly keeps the behavior
the `ccip` image gave it. Do not set `CL_CHAIN_DEFAULTS` on the standalone containers: chainlink-evm
then loads that directory instead, and exits at startup on a file it cannot decode, where the
embedded defaults skip such a file with a warning.

Per-node `Order` carries over, so a converted node keeps the RPC prioritization the operator set. A
node with no `Order` stays at the pool's lowest priority, which is how chainlink-evm treats it too.

A few chain-level settings are fixed by standalone itself, because its runtime has no other mode:
heads stay in memory (`HeadTracker.PersistenceEnabled = false`), the log broadcaster and balance
monitor are off, and transactions go through TXM v2 without forwarders or dual broadcast. A node
config that sets one of these the other way gets a startup warning naming it. So do `KeySpecific`
entries, which name the node's own keys and cannot match the executor's new one, and a
`Transactions.AutoPurge` with no `Threshold` (the detection-API mode Scroll's chain defaults use),
which TXM v2 cannot run, so it is turned off. A setting this release does not recognize, cannot
decode, or whose chainlink-evm rejects it (the node may run a newer chainlink-evm) is dropped by
name, and the chain still starts with everything else; an `[[EVM]]` block whose `ChainID` does not
decode is skipped, and the other chains still start. The set-detection reads the file itself, so a
typo of a real setting is named rather than missed.

If the node config sets no TXM v2 block time, the value comes from a curated per-chain table when
the chain's real block interval is above the two-second floor upstream validation enforces —
Ethereum and its testnets at 12s, Rootstock at 30s, Gnosis at 5s, and similar — and from the
generic 2-second fallback otherwise, which is already the best legal value for a fast chain. The
source is always visible: `txm_block_time_source` in the step 3 diff reads `operator`,
`curated_chain_default`, or `generic_fallback`, and the process that writes to a chain logs the
source when that chain's TXM starts (warn for the generic fallback, info for a curated default; a
chain it only reads from runs no TXM and says nothing). A chain still reporting `generic_fallback`
that is actually slow wants an explicit value agreed with Chainlink Labs before the cutover; the
[TXM v2 assessment](txm-v2-assessment.md) explains the cadence math.

Send-only nodes and the per-node `HTTPURLExtraWrite` and `IsLoadBalancedRPC` settings have no
standalone equivalent and are dropped, as is any other per-node setting beyond the endpoint URLs,
the name, and the selection order. Each one is named at startup: a setting dropped from a node that
is otherwise carried gets its own line, and a send-only node's settings are named on the line that
reports the node itself being dropped, since the node is not carried at all. An operator relying on
a send-only endpoint should add it as a full node.

## A declared chain missing from the config fails the boot

The bootstrap config's `[[chains]]` entries declare the chains the operator runs — they are what
registers the signing key in JD. Every EVM entry is checked against the mounted EVM config at boot:
a declared chain with no section in the config, one whose section fails to convert (no usable RPC
endpoint, an unknown chain ID), or one whose section is present but cannot serve the chain — no RPC
nodes, or settings the chainlink-evm validator rejects — stops the startup with an error naming the
chain, its selector, and the reason. The check builds each declared chain the same way the accessor
factory does at job start, with no network calls, so a section that merely decodes is not mistaken
for a working one. Without the check, that gap would surface only when the first message for the
chain arrived.

Inside the conversion itself an unservable chain is skipped, not fatal: the remaining chains still
convert, and the skip is logged at warn and shown in the step 3 diff under `failed_chains`. That
split is deliberate — a leftover `[[EVM]]` block for a chain the operator no longer serves must not
take down every other chain, while a chain the operator declared as serving is a hard error. The
reverse direction is allowed without complaint: a chain present in the EVM config but not declared
in `[[chains]]` simply sits unused unless a job spec references it.

## Finality checking stays on

The job spec accepts `disable_finality_checkers`, but only standalone mode honors it; CL mode
ignores it and always runs finality checkers. Do not set it on an EVM job: the node never disabled
checking, so the cutover must not either. The field exists for chain families whose standalone
deployments predate this procedure.

## Source logs: RPC or a LogPoller

A CL-mode verifier reads `CCIPMessageSent` logs through the node's LogPoller when the node runs one
(`[Feature] LogPoller = true`), and uses the LogPoller's finality signal in place of the
header-based finality checker. Otherwise it issues `eth_getLogs` per poll. The standalone verifier
does the latter by default: ranges of at most 100 blocks, fed by the in-memory head tracker
described under [Flagged for update](#flagged-for-update). A node config that sets a lower
`LogBackfillBatchSize` caps the range at that value, and a lower `RPCDefaultBatchSize` caps the
header batch below its default of 25, so limits tuned for strict providers carry over. Each poll
re-reads the chain's unfinalized window, so the call count grows with finality depth.

The standalone verifier can also run its own LogPoller, per chain. It is off by default, and it
exists only in the standalone-format EVM config, not in a node TOML:

```toml
[chains.<selector>]
log_poller_source_reader_enabled = true
```

It also needs an EVM secrets file (`EVM_SECRETS_PATH`, default `/etc/evm/secrets.toml`) whose
`[db].url` names the database for the LogPoller's own `evm` schema. That can be the verifier
application database or a separate one; the schema and its version table do not collide with the
verifier's. The process refuses to start if a chain turns the reader on and `[db]` is missing.
With a node TOML mounted, as this procedure says, every chain reads over RPC, so a node that ran
its LogPoller changes reader at the cutover.

Nothing migrates across the cutover either way. The node's LogPoller tables are a cache of chain
data, and the standalone verifier starts without a checkpoint: its first scan begins 500 blocks
behind the finalized head. Messages finalized after the node stopped but before that block are
never read by this verifier, whichever reader it runs. On a 12-second chain 500 blocks is well over
an hour; on a sub-second chain it is a couple of minutes, so most of a cutover window is not
covered. The rest of the committee verifies those messages; see
[How many operators can migrate at once](#how-many-operators-can-migrate-at-once).

What changes when the standalone LogPoller is on:

1. Every start replays. The startup load takes the EVM database lease, waits until the
   checkpoint is finalized, registers the filter, and replays the LogPoller from the checkpoint,
   normally about one finality depth. Until it finishes, the chain reports not ready; confirm
   `Executing replay finished` in the LogPoller log for the requested start block.
2. The database named by `[db].url` holds the LogPoller's blocks and 30 days of `CCIPMessageSent`
   logs per OnRamp. Size it, and its backups, for that.
3. One writer per EVM database. A second process on the same database waits on the lease, and its
   LogPoller chains stay not ready until the first one releases it.
4. Recovery reads the LogPoller's tables. A checkpoint rewound with `chain-statuses
   set-finalized-height` is refilled over RPC by the next start's replay. A live replay of a range
   older than the log retention reads nothing. A chain disabled by a LogPoller finality violation
   is not recovered by `reset-reader` or `replay`; follow
   [Resolving a Finality Violation](../runbooks/resolving-finality-violation.md), which uses
   `verifier ccv blocks find-lca` and `remove-blocks`.
5. A stalled LogPoller pins the reader's heads to its last processed block, so the reader stops
   advancing. Watch `verifier_source_reader_last_processed_finalized_block` against the chain
   head. The standalone verifier also reports `source unhealthy` on `/health` when the LogPoller
   itself reports unhealthy; a CL-mode verifier does not.
6. Before rolling back to an older image, remove `log_poller_source_reader_enabled`: older binaries
   reject the key. The `evm` schema's migrations are forward-only, like the verifier's own.

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

A mistake in the operator's steps surfaces in one of two ways. The export or the boot fails its
`expected_id` check, so a wrong key never reaches JD; or the verifier changeset refuses to propose
because the chain is not registered in JD for that operator. The changeset itself is offchain-only
and never proposes a signer change: it writes the signer it reads from JD into the job's
`signer_address`, which is why step 9 compares that field with the address read before the cutover.

When the job starts, the standalone verifier also compares its keystore address with the job's
`signer_address` and refuses to run on a mismatch. The error points back to `[key_import]` rather than
allowing a wrong key to fail later at aggregator quorum.

The import itself runs only when the key is absent, so it is a no-op on every restart after the
first, and the export and password files are never read again. They stay mounted until Chainlink
Labs confirms the cutover anyway, in case the import has to be redone; then the operator removes
them (see [After Chainlink Labs confirms the cutover](#after-chainlink-labs-confirms-the-cutover)).
Keep the `[key_import]` block: with the key present the import is skipped, but `expected_id` is
still checked against the stored key on every boot, and a verifier whose bootstrap database was
lost fails to start rather than generating a new key.

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
- `/keystore/reader/getaddresses` returns the EVM address of a secp256k1 key; steps 5 and 7 use it.
- On images built from chainlink-ccv #1521 on, `/health/live` (a static `alive`) and
  `/health/ready` (the same as `/ready`) serve the standard probe paths.

This server starts only after the bootstrapper's database migrations, the keystore setup (including
the key import), and the JD lifecycle start, which on a restart also starts the cached job. The JD
connection itself is made in the background, so the server comes up before the process is
registered in JD.

The application's own server carries the real health signal. By default the verifier listens on
8100 and the executor on 8101; each job's app config can override its own port with
`http_listen_port`. Its `/health` returns 200 with `status: "ready"` when healthy, or 200 with
`status: "degraded"` and the skipped component named. A process with no usable chain or component
returns 503. Degraded can be expected during startup or for intentionally unsupported chains, so
read the component report rather than treating any degraded response as a failure. A verifier chain
whose log scans or finality checks keep failing for the staleness threshold is named there too,
as is `jd.UpdateNode` while JD has not accepted the node's chain configs (retried with backoff).
The same port serves `/metrics` with chainlink-evm's per-chain Prometheus series, such as
`txm_num_nonce_gaps` and `txm_reached_max_attempts`. The verifier also serves `/stats`.

A stalled LogPoller is the case to watch outside `/health`; see
[Source logs](#source-logs-rpc-or-a-logpoller).

For a Kubernetes deployment, probe the bootstrapper's port. The application server only starts once
JD proposes the job (step 9), so a liveness probe on it restarts the pod until then, and a readiness
probe on `/ready` holds every rollout until then. Use the bootstrapper's `/health` (or
`/health/live`) for both probes, and add a startup probe with a few minutes of budget to cover the
boot described above. Neither probe can see a failed component, so watch the application `/health`
and the bootstrapper's `/ready` from monitoring. Run one replica with a `Recreate` update strategy:
a rolling update briefly runs two processes on one signing or transmitter key.

## How many operators can migrate at once

The committee keeps verifying as long as `threshold` members are up. From step 4 (node stopped)
until the standalone verifier is confirmed (steps 9 and 10), an operator counts toward neither side,
so the number that can be mid-cutover at once is the committee size minus the threshold. The
default committee has a threshold of 9 on every chain in `prod_mainnet`, but its size is 14, 15 or 16
depending on the chain, so the budget is 5 to 7. Use the smallest committee any of the operator's
chains belongs to.

Derive the number from the committee's live configuration rather than reusing one of these: it moves
with committee size and threshold. Because the signing key carries over, a migrated operator counts
toward the threshold again as soon as its standalone verifier is up; the window that consumes
budget is steps 4 to 9.

That holds for new messages only. Each migrating verifier never reads the messages finalized during
its window beyond its 500-block lookback (see [Source logs](#source-logs-rpc-or-a-logpoller)), and
those messages never get its signature. With several operators mid-cutover on a fast chain, the
messages from the overlapping windows are verified by fewer members than usual, and at the full
budget by exactly `threshold`, so one more failure leaves them unverified until source recovery.
Keep windows short and stay under the budget rather than at it.

## Flagged for update

- **CCIP-12871** adds a `ccv migrate` command for step 7: it reads the transmitter address and routes
  the balances from the node's legacy per-chain transmitters into it. Step 7 becomes one command.
- **EVM service state.** The verifier application database already persists chain statuses and
  queues, separately from its bootstrap database. EVM head-tracker and TXM state remain in memory;
  see the [TXM v2 assessment](txm-v2-assessment.md) for the transaction-recovery risk. The known
  delta until then: a restart starts the head tracker cold — it re-syncs from RPC instead of
  resuming from persisted heads the way the node did, which costs catch-up time on restart, not
  correctness.
- **LogPoller from a node TOML.** The standalone LogPoller reader can only be turned on in the
  standalone-format EVM config, so an operator who mounts their node TOML, as step 3 says, reads
  over RPC after the cutover even if the node ran its LogPoller. See
  [Source logs](#source-logs-rpc-or-a-logpoller).
- **Executor job delivery.** `ApplyExecutorConfig` proposes by NOP alias and cannot reach the
  executor's separate record, so step 9 proposes the executor job by hand with `jd_propose_job`. A
  changeset that can target a standalone operator's executor record removes that step.
