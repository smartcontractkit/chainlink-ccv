# Staging migration: CL mode to standalone CCV

Audience: CCV team. Scope: the `staging_testnet` environment, meaning the 21-node `chainlink-ccv`
DON in the stage cluster (JD aliases `chainlink-ccv-staging-0..20`, k8s nodes
`chainlink-ccv-0..20`). The default committee has two aggregators; each of its five EVM chain
configs lists 10 of the 21 nodes with threshold 6. The chains are ethereum-sepolia,
arbitrum-sepolia, base-sepolia, polygon-amoy, and avalanche-fuji. The two Canton committee
verifiers in the same topology already run `mode = "standalone"`, so the per-node flip has
in-file precedent. (The `staging-migration` environment is for on-chain migration work and is not
used here.)

The goal is to convert the staging committee to standalone node by node, proving the
CL-to-standalone cutover end to end before prod runs it. This environment is live: while a node is
mid-cutover, the chains it serves run one committee member short, so the pace is one node at a
time with a soak between nodes. This document is written to be executed; the commands are
copy-pasteable given the variables in "Conventions". Placeholders in angle brackets name the
prerequisite or open question that produces them.

---

## Background

Today each node runs both CCV jobs (`ccvcommitteeverifier`, `ccvexecutor`) on a Chainlink node
("CL mode"). Standalone moves them to two processes, a verifier and an executor, each with its own
databases, keystore, and JD node record. The verifier's signing key is exported from the node and
imported into the standalone verifier, so the on-chain committee signer set never changes. The
executor instead generates a fresh transmitter key that we fund; nothing on chain names the
transmitter, so no reconfiguration is needed.

Reference procedure: `chainlink-ccv/docs/migration/evm-cl-to-standalone.md`, written for external
operators. This document adapts it for staging, where one team does both halves.

## What is already done

- Code parity between the modes is closed. All tracked in-repo gaps are resolved: signer guard,
  disabled-chain restore, executor defaulting, poll/head-fetch timing, NTP backoff, observability
  (health endpoints, metrics wiring), config conversion warnings. See `cutover-tickets.md`
  (A1-A4, B1-B7, C1-C5, D1-D6).
- The cutover mechanism itself is tested end to end by `TestE2EMigration_CLToStandalone`
  (`chainlink-ccv/build/devenv/tests/e2e/smoke_migration_test.go`).
- Migration tooling landed 20 Aug 2026. Note: this batch currently lives on the `tt/stagingPrep`
  branch of chainlink-ccv, not on main. It has to merge before P2, since the images we deploy must
  contain it.
  - `ccv migrate export --expected-id <addr>` fails the export if the exported key doesn't match
    the JD-registered signing address. This catches a wrong-bundle export while the node is
    still up.
  - `ccv migrate inspect-config --config <node.toml>` prints the effective per-chain settings the
    standalone processes will run (finality, TXM block time with the 2s fallback flagged, node
    set) plus every node setting the conversion drops. This is the pre-cutover settings diff.
  - The 2s TXM block-time fallback now warns per chain at startup instead of applying silently.

## Hard rules (from the runbook)

1. One node at a time. Each EVM chain config has 10 members and threshold 6, so a chain tolerates
   at most 4 of its members mid-cutover; with one node down every chain it serves still runs 9 of
   6. One at a time is safe on every chain without doing per-chain arithmetic, and it mirrors the
   prod discipline.
2. Export while the node is up; stop the node before the standalone verifier starts. One JD
   record cannot have two owners.
3. Never boot the verifier without its `[key_import]` block. Key generation happens at process
   startup: a verifier that comes up once without the block generates its own signing key, and
   adding the block afterwards will not fix it.
4. `ApplyVerifierConfig` must produce no contract transaction. A proposed signer change means the
   imported key is wrong. Stop.
5. After the standalone verifier job first starts, re-apply the disabled flag for any chain that
   was disabled on the node (the flag lives in the node database and does not carry over), and
   confirm it before calling the cutover done.

## Conventions

Every command below assumes this block has been pasted into the shell. AWS SSO expires every 8h.

```sh
aws sso login --sso-session griddle-session

# kubeconfig context names as in chainlink-ccv-deploy AGENTS.md; adjust to your kubeconfig
export CTX=platform-ccip-stage                        # cluster reads, exec, scale
export CTX_ENG=griddle-platform-ccip-stage-engineer   # secret creation (RBAC: create, not patch)
export NS=chainlink-ccv

CCV=~/dev/dev/chainlink-ccv
CLD=~/dev/dev/chainlink-deployments
DEPLOY=~/dev/dev/chainlink-ccv-deploy

# per cutover; i = 0..20
i=1
NODE=chainlink-ccv-staging-$i               # JD alias, topology alias
CL=chainlink-ccv-$i                         # the node's k8s deployment, service, secret prefix
VER=ccv-standalone-verifier-$i              # standalone verifier release (created in P7)
EXE=ccv-standalone-executor-$i              # standalone executor release (created in P7)
EXPECTED_ID=<from P8>                       # this node's OnchainSigningAddress from JD
```

The alias-to-node mapping (`chainlink-ccv-staging-$i` to `chainlink-ccv-$i`) is assumed 1:1 by
index. The export in step 3 verifies it for free: `--expected-id` carries the alias's JD signing
address, and the export fails if the node behind the port-forward holds a different key.

Deploys are IssueOps: branch in chainlink-ccv-deploy, open a PR (ready, not draft), comment
`.deploy stage` on it, thumbs-up the confirmation comment. There is no auto-deploy on merge, and
the `.deploy` comment deploys every instance in the env. `gcli deploy render -e stage` and
`gcli helm template -e stage -N <instance> -c griddle.yaml` preview locally.

Pipeline runs in chainlink-deployments are either local
(`go run ./domains/ccv/cmd durable-pipeline run --environment staging_testnet --input-file
<name>.yaml`, with `--dry-run` first) or the canonical path: commit the input YAML under
`domains/ccv/staging_testnet/durable_pipelines/inputs/`, open a PR, comment `/run-pipelines`.
Either way the run performs real JD and on-chain operations.

## Prerequisites (before the first node migrates)

### P0. Local pipeline and JD auth setup

staging_testnet already registers the shared CCV pipelines (`apply-verifier-config`,
`apply-executor-config`, `jd_*`), unlike staging-migration, so no code change is needed. Verify,
and set up local JD auth for CLI runs (`domains/ccv/.config/local/` is empty today):

```sh
cd $CLD
go run ./domains/ccv/cmd durable-pipeline list --environment staging_testnet
go run ./domains/ccv/cmd domain config local create --domain ccv --env staging_testnet
# fill in the JD Cognito credentials it scaffolds
```

### P1. Consolidate verifier jobs (run while still in CL mode)

Two aggregators means each node runs two `ccvcommitteeverifier` jobs for the default committee
today; standalone runs one. Aggregator HMAC creds keep working: legacy `verifier_id`s become
`secret_name`s.

```sh
cat > $CLD/domains/ccv/staging_testnet/durable_pipelines/inputs/consolidate_verifier_jobs.yaml <<'EOF'
environment: staging_testnet
domain: ccv
merge-proposals: true
changesets:
  - apply-verifier-config:
      payload:
        committeeQualifier: "default"
        defaultExecutorQualifier: "default"
        chainFamily: evm
        consolidateAggregators: true
        revokeOrphanedJobs: true
EOF
cd $CLD
go run ./domains/ccv/cmd durable-pipeline run --environment staging_testnet \
  --input-file consolidate_verifier_jobs.yaml --dry-run
# then without --dry-run, or commit + /run-pipelines
```

Two cautions. First, no archived input in the repo has used
`consolidateAggregators`/`revokeOrphanedJobs` yet (the payload keys come from the resolver struct
fields, matched case-insensitively), so treat the first dry run as the test of the spelling.
Second, node 0 is also the sole member of the `secondary` committee, so it carries a
secondary-committee verifier job this consolidation does not touch and its preflight will show two
jobs; see open question 1 and leave node 0 for last.

### P2. Images

Build and publish the standalone verifier and executor images to the internal ECR from a
chainlink-ccv commit that includes the 20 Aug migration tooling (merge `tt/stagingPrep` first).
The existing `manual-build.yaml` workflow in chainlink-ccv publishes to the private ECR the stage
cluster pulls from.

### P3. Charts and config dir

The `committee-verifier-base` chart already exists in chainlink-ccv-deploy
(`deploy/charts/committee-verifier-base`, v0.1.1, already listed in `build.charts.inventory`) with
zero deploy instances; the verifier instances can point straight at it. No executor chart exists
anywhere, so create `deploy/charts/standalone-executor` with `committee-verifier-base` as the
template. The canton values (`deploy/config/staging/committee-verifier-canton/staging.yaml`) show
the secrets-mount pattern to copy: one versioned secret per instance, `subPath`-projected onto the
paths the process reads (`/etc/bootstrap/secrets.toml`, `/etc/committee-verifier/secrets.toml`).
Also create the config dir `deploy/config/staging/ccv-standalone/`.

### P4. Databases (3 per node)

Verifier-bootstrap, verifier-app, executor-bootstrap. They cannot share a database (both migration
runners use goose's default version table). 63 databases if the whole committee migrates;
provision at least the next node's three before its window. Edit
`$DEPLOY/deploy/config/staging/database-provisioner/database-provisioner.yaml`; map keys must stay
at or under 43 chars (the composition appends `-provider-sql-config` and the result is a 63-char
k8s label). Set `connectionSecret.name` explicitly. Node 1's block, as the model:

```yaml
databases:
  ccv-sa-1-verifier-bootstrap:
    databaseClusterName: chainlink-ccv-dons
    databaseName: ccv_sa_1_verifier_bootstrap
    connectionSecret:
      name: ccv-sa-1-verifier-bootstrap-database-connection
  ccv-sa-1-verifier-app:
    databaseClusterName: chainlink-ccv-dons
    databaseName: ccv_sa_1_verifier_app
    connectionSecret:
      name: ccv-sa-1-verifier-app-database-connection
  ccv-sa-1-executor-bootstrap:
    databaseClusterName: chainlink-ccv-dons
    databaseName: ccv_sa_1_executor_bootstrap
    connectionSecret:
      name: ccv-sa-1-executor-bootstrap-database-connection
```

Deploy (PR + `.deploy stage`), then verify:

```sh
kubectl --context $CTX -n $NS get databasecluster
kubectl --context $CTX -n $NS get secret ccv-sa-$i-verifier-app-database-connection
```

Each connection secret carries `POSTGRES_HOST/PORT/USER/PASSWORD/DB`.

### P5. Per-chain txm_block_time

Agree the values for the five chains (open question 3), then set
`Transactions.TransactionManagerV2.BlockTime` per chain in the EVM TOML the standalone processes
mount; that is the only TXM setting the conversion carries over. Verified in cutover step 2 with
`inspect-config`.

### P6. Secrets per node

Three TOMLs per node: verifier bootstrap secrets (bootstrap DB `[db].url` plus
`[keystore].password`), verifier app secrets (app DB `[db].url` plus `[[aggregators]]` HMACs,
reusing the creds the CL jobs use today, keyed by the P1 `secret_name`s), executor bootstrap
secrets. Schemas: `docs/config/bootstrap/secrets.documented.toml` and
`docs/config/verifier/secrets.documented.toml` in chainlink-ccv. Compose the DB URLs from the P4
connection secrets:

```sh
db_url() { kubectl --context $CTX -n $NS get secret "$1" -o go-template='postgres://{{index .data "POSTGRES_USER" | base64decode}}:{{index .data "POSTGRES_PASSWORD" | base64decode}}@{{index .data "POSTGRES_HOST" | base64decode}}:{{index .data "POSTGRES_PORT" | base64decode}}/{{index .data "POSTGRES_DB" | base64decode}}'; }
db_url ccv-sa-$i-verifier-bootstrap-database-connection
```

Create versioned secrets (create-not-patch RBAC; a change later means `-v2` plus a values repoint,
per the canton README workflow):

```sh
kubectl --context $CTX_ENG -n $NS create secret generic $NODE-verifier-secrets-v1 \
  --from-file=bootstrap-secrets.toml=/tmp/$NODE-verifier-bootstrap-secrets.toml \
  --from-file=verifier-secrets.toml=/tmp/$NODE-verifier-app-secrets.toml
kubectl --context $CTX_ENG -n $NS create secret generic $NODE-executor-secrets-v1 \
  --from-file=bootstrap-secrets.toml=/tmp/$NODE-executor-bootstrap-secrets.toml
```

### P7. Griddle releases, verifiers at zero replicas

Two entries per node in `$DEPLOY/griddle.yaml` under the stage env, modeled on the canton
entries; add them per migration batch rather than all 42 upfront. `ccip_env: stage` is required
(the image-sync-check workflow errors without it). Shape:

```yaml
    - name: ccv-standalone-verifier-1
      namespace: chainlink-ccv
      path: deploy/charts/committee-verifier-base
      ccip_env: stage
      config:
        - deploy/config/staging/ccv-standalone/verifier-common.yaml
        - deploy/config/staging/ccv-standalone/verifier-1.yaml
      settings:
        install_timeout: 5m0s
        rollback_timeout: 5m0s
        upgrade_timeout: 5m0s
```

The executors may run immediately (`replicas: 1`); they just generate their transmitter key and
idle. The verifiers must not: rule 3 means a verifier's first boot has to happen inside its node's
cutover window, after its key-import secret exists. Set `replicas: 0` in each verifier's values.
That keeps the Deployment object present so a later scale works, and Flux drift detection is
configured to ignore `/spec/replicas`, so a manual scale is not fought by the reconciler (it is
only overwritten by the next actual deploy of that release). Preview before deploying:

```sh
cd $DEPLOY && gcli helm template -e stage -N ccv-standalone-verifier-1 -c griddle.yaml
```

### P8. expected_id per node, from JD

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json
go run ./domains/ccv/cmd validate nop-support -e staging_testnet
```

Record each node's `OnchainSigningAddress`; that value is `$EXPECTED_ID` in step 3. While here,
also record each node's current CSA key: the rollback path needs it (step 7).

### P9. Funding source and balance alerts

Identify what funds staging node accounts today (open question 2) and wire external balance
alerts for each new transmitter address on the five testnets. The standalone executor does not run
the node's balance monitor; an unfunded account surfaces as failed broadcasts, not as an alert.

## The cutover, per node (one at a time)

### 1. Preflight

```sh
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink admin login --file /v2Secret/.api
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink jobs list
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink node ccv chain-statuses list
```

Expect exactly one `ccvcommitteeverifier` job (post-P1; node 0 is the exception, see open
question 1) and one `ccvexecutor` job. Record any chain-status row with `disabled = true`; step 10
needs the selectors.

### 2. Diff the config

Pull the node's effective EVM TOML (render the release locally with
`gcli helm template -e stage -N chainlink-ccv -c griddle.yaml` and extract it from the ConfigMap,
or read the live ConfigMap), then:

```sh
cd $CCV
go run ./cmd/verifier/committee ccv migrate inspect-config --config /tmp/node-$i.toml
```

Review the warnings and per-chain effective settings; accept or correct each deviation. No chain
may show `txm_block_time_is_default: true` (that is the 2s fallback; fix the config per P5).

### 3. Export the verifier key

```sh
kubectl --context $CTX -n $NS get secret $CL-v2 -o jsonpath='{.data.\.api}' | base64 -d > /tmp/api-creds.txt
kubectl --context $CTX -n $NS port-forward svc/$CL 6688:6688 &   # leave running
cd $CCV
go run ./cmd/verifier/committee ccv migrate export \
  --node-url http://localhost:6688 --api-creds /tmp/api-creds.txt \
  --out-dir /tmp/migration-$i --expected-id $EXPECTED_ID
```

Writes `ocr2.json`, `export-password.txt`, and `verifier.key_import.toml` (the `[key_import]`
block, address pre-filled) into `/tmp/migration-$i`. If the export fails on the expected-id check,
stop: either the wrong bundle or the wrong node is behind the port-forward. Do not retry with a
different value.

### 4. Create the key-import secret and prepare the start PR

```sh
kubectl --context $CTX_ENG -n $NS create secret generic $NODE-keyimport-v1 \
  --from-file=key.json=/tmp/migration-$i/ocr2.json \
  --from-file=export-password.txt=/tmp/migration-$i/export-password.txt
```

Then prepare (do not deploy yet) one chainlink-ccv-deploy PR that: mounts that secret into the
verifier at `/etc/ccv/migration/`; adds the `[key_import]` block from `verifier.key_import.toml`
to the verifier's bootstrap config; sets the verifier's `replicas: 1`; and adds this node's index
to `maintenanceMode.specificNodes` in `deploy/config/staging/chainlink-ccv/overrides.yaml`, which
is the durable form of step 5.

### 5. Stop the CL node

```sh
flux --context $CTX suspend helmrelease chainlink-ccv -n $NS   # freeze the DON release for the window
kubectl --context $CTX -n $NS scale deploy/$CL --replicas=0
kubectl --context $CTX -n $NS get pods | grep $CL              # gone; the port-forward from step 3 drops
```

The suspend keeps any concurrent deploy from touching the DON release mid-window; step 11 resumes
it, at which point the maintenanceMode entry from the step 4 PR holds the node at zero durably.

### 6. Start the standalone pair

Comment `.deploy stage` on the step 4 PR and confirm. Then check what is checkable now. No job
exists yet, so the app ports (8100/8101) serve nothing and bootstrap `/ready` stays 503; that is
expected here. The images ship busybox wget, not curl.

```sh
kubectl --context $CTX -n $NS exec deploy/$VER -- wget -qO- http://localhost:9988/health   # {"status":"ok"}
kubectl --context $CTX -n $NS exec deploy/$EXE -- wget -qO- http://localhost:9988/health
kubectl --context $CTX -n $NS logs deploy/$VER | grep -i expected_id                       # must print nothing
```

### 7. CSA handoff

```sh
for R in $VER $EXE; do
  kubectl --context $CTX -n $NS exec deploy/$R -- wget -qO- \
    --post-data='{"KeyNames":["bootstrap_default_csa_key"]}' \
    http://localhost:9988/keystore/reader/getkeys; echo
done
# PublicKey in the response is base64; JD takes hex:
echo '<PublicKey>' | base64 -d | xxd -p -c 999
```

Repoint the node's existing JD record at the verifier's CSA key (this keeps the node ID and
alias), and register the executor as a new JD node. Record the old CSA key first; rollback is
repointing the record back at it.

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json     # node id + current csa key
go run ./domains/ccv/cmd jd node update -e staging_testnet -i <node_id> -k csa_key -v <verifier_csa_hex>
go run ./domains/ccv/cmd jd node register -e staging_testnet \
  -n ccv-standalone-executor-$i -a <executor_csa_hex> \
  -l product=ccv -l environment=staging_testnet
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json     # wait: both connected
```

Wait until JD reports both connected before step 9: a job proposed to a record whose owner has not
dialed in sits unclaimed. Two cautions: check `jd node update --help` for the `-k` spelling
(`csa_key` vs `csa-key` differs between framework versions), and `jd node register` appends the
new node id to `domains/ccv/staging_testnet/nodes.json`, which is part of the commit.

### 8. Fund the executor

```sh
kubectl --context $CTX -n $NS logs deploy/$EXE | grep executor_evm_transmitter_key
```

The line is `key created` (or `key already exists` on a restart) and the address is in the
`evmAddress` field; it is emitted at process start. Fund it on all five testnets from the P9
source, for example:

```sh
for RPC in $RPC_SEPOLIA $RPC_ARB_SEPOLIA $RPC_BASE_SEPOLIA $RPC_AMOY $RPC_FUJI; do
  cast send <evmAddress> --value 0.5ether --rpc-url $RPC --private-key $FUNDER_KEY
done
```

Attach the P9 balance alerts. The old per-chain transmitter balances stay put: they are testnet
tokens and the rollback path, so nothing gets swept in staging.

### 9. Flip the mode

Append the mode to the node's block in `domains/ccv/staging_testnet/topology.toml`, exactly as the
canton entries in the same file already do:

```toml
[[nop_topology.nops]]
alias = "chainlink-ccv-staging-1"
name = "chainlink-ccv-staging-1"
mode = "standalone"
```

Write the input and run both changesets, scoped to this node:

```sh
cat > $CLD/domains/ccv/staging_testnet/durable_pipelines/inputs/cutover_node_$i.yaml <<EOF
environment: staging_testnet
domain: ccv
merge-proposals: true
changesets:
  - apply-executor-config:
      payload:
        executorQualifier: "default"
        targetNops: ["$NODE"]
  - apply-verifier-config:
      payload:
        committeeQualifier: "default"
        defaultExecutorQualifier: "default"
        chainFamily: evm
        targetNops: ["$NODE"]
EOF
cd $CLD
go run ./domains/ccv/cmd durable-pipeline run --environment staging_testnet \
  --input-file cutover_node_$i.yaml --dry-run
# then without --dry-run
```

Rule 4 applies here: the verifier changeset must produce no contract transaction; a proposed
signer change means the imported key is wrong, stop. The processes approve their own job specs, so
nothing needs accepting in the JD UI. Once the jobs start:

```sh
kubectl --context $CTX -n $NS logs deploy/$VER | grep -i signer_address    # must print nothing
kubectl --context $CTX -n $NS exec deploy/$VER -- wget -qO- http://localhost:8100/health
kubectl --context $CTX -n $NS exec deploy/$EXE -- wget -qO- http://localhost:8101/health
kubectl --context $CTX -n $NS exec deploy/$VER -- wget -qO- http://localhost:9988/ready   # now 200
```

### 10. Re-apply disabled chains, if step 1 recorded any

This can only happen now: the standalone `verifier_id` and the app-database rows exist only once
the job has started. The CLI reads the app DB from the mounted verifier secrets file, so exec in
the verifier container hits the right database. The flag is read at start, hence the restart.

```sh
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses list   # note verifier_id
kubectl --context $CTX -n $NS exec deploy/$VER -- pkill -STOP -f verifier                 # quiesce
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses disable \
  --chain-selector <sel> --verifier-id <standalone-verifier-id>
kubectl --context $CTX -n $NS rollout restart deploy/$VER
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses list   # disabled = true
```

### 11. Prove it, then clean up

Send a message across a lane this node verifies (the same tooling stage smoke tests use today) and
confirm it is verified and executed. Confirm on chain that the committee signer set is unchanged.
Then:

```sh
flux --context $CTX resume helmrelease chainlink-ccv -n $NS   # maintenanceMode now holds $CL at 0
rm -rf /tmp/migration-$i /tmp/api-creds.txt
```

Commit the chainlink-deployments changes (topology.toml, the input file, nodes.json). The CL
node's CCV job specs get removed the next time that node runs; while it sits at zero replicas this
is not blocking.

### 12. Soak, then repeat for the next node

## Validation before calling it done

- Canary restart under traffic: `kubectl --context $CTX -n $NS delete pod <executor-pod>`
  mid-flight and watch TXM v2 recover. Nonce-gap detection waits 90 seconds for old transactions
  to confirm, then submits fee-bumped replacements; no message may end up stuck. This is the known
  residual risk, since TXM v2 keeps transactions in memory.
- Head-tracker cold start: a restarted process re-syncs from RPC instead of resuming persisted
  heads. That costs catch-up time, not correctness; measure it once and decide whether it is
  acceptable.
- Dashboards: source-reader head gauges, critical-invariant counter, OffRamp read latency,
  transmit failures, and the new transmitter balance alerts.
- Rollback path: scale the CL node back up and repoint its JD record at the CSA key recorded in
  step 7 (`jd node update -i <node_id> -k csa_key -v <original_csa_hex>`). Exercise it on purpose
  at least once before the fleet is deep into the migration.

## Open questions for the team

1. Node 0 is the sole member of the `secondary` committee (threshold 1 on all five chains), so
   after P1 it still runs two verifier jobs and fails the one-job preflight. Do we retire the
   secondary committee, or give node 0 a second standalone verifier for it? Either way node 0
   migrates last.
2. What is the staging funding source for node accounts, and who owns sending from it? (P9)
3. Per-chain `txm_block_time` values for the five chains. Proposal to react to: sepolia 12s,
   arbitrum-sepolia 1s, base-sepolia 2s, amoy 2s, fuji 2s. Needs agreement before P5.
4. Do we cut the first node over in a team session, as the dress rehearsal for the prod runbook?
   I'd say yes; a clean run is also the validation A5 still needs. Since staging_testnet is live,
   agree the window with whoever depends on stage lanes.

## What staging does not decide

Prod batching (16 members, threshold 9, so at most 7 nodes mid-cutover at once), external
operator comms, public image publishing (F2), operator-facing docs (F3), and sweeping prod
transmitter balances (F1). Those get decided later, with staging results in hand.
