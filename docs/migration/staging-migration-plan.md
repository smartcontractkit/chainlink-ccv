# Staging migration: CL mode to standalone CCV

Audience: CCV team. Scope: the `staging_testnet` environment, meaning the 21-node `chainlink-ccv`
DON in the stage cluster (JD aliases `chainlink-ccv-staging-0..20`, k8s nodes
`chainlink-ccv-0..20`). The default committee has two aggregators; each of its five EVM chain
configs lists 10 of the 21 nodes with threshold 6. The chains are ethereum-sepolia,
arbitrum-sepolia, base-sepolia, polygon-amoy, and avalanche-fuji. The two Canton committee
verifiers in the same topology already run `mode = "standalone"`, so the per-node flip has
in-file precedent. (The `staging-migration` environment is for on-chain migration work and is not
used here.)

The staging committee proved the CL-to-standalone cutover end to end before prod ran it. Node 1
was the canary; the remaining nodes used two waves: 2–6, then 7–20 plus node 0. Each wave had one
deployment PR and one combined CLD PR. **All 21 staging EVM nodes are now standalone.** The final
wave deployed in [chainlink-ccv-deploy #523](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/523)
and activated in [chainlink-deployments #21107](https://github.com/smartcontractkit/chainlink-deployments/pull/21107).
Do not rerun its completed activation input.

This environment was live during migration: while a node was mid-cutover, its chains ran one
committee member short, and the aggressive waves could temporarily run below threshold. That was
accepted only for staging and must not be copied to prod. Keep this document as the per-node
procedure and historical record for prod-testnet, not as a request to repeat staging. Commands are
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

Technical reference: [EVM standalone verifier and executor](../verifier/evm-standalone.md).
This document adapts the CL-to-standalone cutover for staging, where one team does both halves.

## What is already done

- Code parity between the modes is closed for everything tracked in `cutover-tickets.md`
  (A1-A4, B1-B7, C1-C5, D1-D6): signer guard, disabled-chain restore, executor defaulting,
  poll/head-fetch timing, NTP backoff, observability (health endpoints, metrics wiring), config
  conversion warnings. One delta has appeared since: a CL-mode verifier on a node with the
  LogPoller enabled reads source logs through the node's LogPoller (#1482), while the standalone
  verifier reads over RPC unless its own LogPoller is turned on. See open question 4.
- Chain-setting parity: standalone carries the node config's chain-level settings over and resolves
  the same chain defaults as the `ccip` node image (chainlink-evm's plus CCIP's, embedded). Compared
  setting by setting against the DON config, the five committee chains run exactly what the CL nodes
  run, apart from what standalone fixes itself (heads in memory, TXM v2). The staging values pin a
  build that includes it (P2).
- `TestE2EMigration_CLToStandalone` (`build/devenv/tests/e2e/smoke_migration_test.go`) tests the
  key export, the import, and the JD record handoff end to end. It does not test how this plan
  delivers jobs: the test proposes the CL node's existing specs straight to the new records by JD
  node ID, while this plan runs `apply-verifier-config` for the verifier and `jd_propose_job` for
  the executor (step 9).
- Migration tooling (`ccv migrate`): key export with an expected-address check, the
  pre-cutover settings diff, and a per-chain warning when the generic TXM block-time
  fallback fires.
  - `ccv migrate export --expected-id <addr>` fails the export if the exported key doesn't match
    the JD-registered signing address. This catches a wrong-bundle export while the node is
    still up.
  - `ccv migrate inspect-config --config <node.toml>` prints the effective per-chain settings the
    standalone processes will run (finality, `txm_block_time`, `txm_block_time_source` —
    `operator`, `curated_chain_default`, or `generic_fallback` — and node set), any
    unconvertible `[[EVM]]` blocks under `failed_chains`, plus every node setting the conversion
    drops. This is the pre-cutover settings diff.
  - Curated per-chain TXM block times (`curatedTXMBlockTimeByChainID` in
    `integration/pkg/accessors/evmconfig/chainlink_config.go`, PR #1461) supply `12s` for Ethereum
    Mainnet and Ethereum Sepolia (and chain-appropriate values for other >2s chains), while
    <=2s chains use the `2s` floor (`DefaultTXMBlockTime = 2s`, the minimum `chainlink-evm`
    accepts).
  - Startup checks declared `[[chains]]` against `EVM_CONFIG_PATH` at boot
    (`chainaccess.CheckDeclaredChainCoverage`, failing fast if a declared chain is missing or in
    `failed_chains`). Once a job starts, per-chain reader/writer resolution failures are logged
    and tolerated as long as at least one chain starts (`cmd/verifier/servicefactory.go`,
    `cmd/executor/service.go`, PRs #1496/#1497/#1507), reporting `"status": "degraded"` with
    per-component details on the app server's `/health` (8100 verifier, 8101 executor; PR #1476).

## Hard rules (from the runbook)

1. Use node 1 as the canary, then the two staging waves above, validating each before the next.
   Each EVM chain config has 10 members and threshold 6, so the normal budget is at most 4 members
   mid-cutover. The aggressive staging waves can temporarily go below threshold; that is an accepted
   staging risk, not a safe-production-budget claim. Prod still needs per-chain arithmetic and its
   own batching discipline.
2. Export while the node is up; stop the node before the standalone verifier starts. One JD
   record cannot have two owners.
3. Never boot the verifier without its `[key_import]` block. Key generation happens at process
   startup: a verifier that comes up once without the block generates its own signing key, and
   adding the block afterwards will not fix it.
4. The `signer_address` that `apply-verifier-config` writes into the node's verifier job in step 9
   must equal `$EXPECTED_ID`. The changeset is offchain-only and never proposes a signer change,
   so that field is where a wrong key would show. A different value means the wrong key was
   imported. Stop.
5. After the standalone verifier job first starts, re-apply the disabled flag for any chain that
   was disabled on the node (the flag lives in the node database and does not carry over), and
   confirm it before calling the cutover done.
6. From P1 on, every EVM `apply-verifier-config` input sets `consolidateAggregators: true`. The
   flag is read per run, not stored: a run without it goes back to one job per aggregator, and a
   standalone verifier keeps only the last job it receives, so it would write to one aggregator.
7. During the recorded migration, `jd_propose_job` preserved each executor's exact spec. Reconcile
   that generic proposal into canonical `standalone`/`appConfig` metadata before generating NOP
   state or relying on later executor routing. Tooling including #1590 can instead run
   `apply-executor-config` with the executor's `executor_node_name` or `ExecutorNodeID`; without
   one of those references or reconciled metadata, it must fail rather than target the verifier's
   NOP alias. Never run an unscoped legacy executor input during cutover.

## Conventions

Every command below assumes this block has been pasted into the shell. AWS SSO expires every 8h.

```sh
aws sso login --sso-session griddle-session

# Current kubeconfig context names; adjust if your profile prefix differs.
export CTX=griddle-platform-ccip-stage-teamccipadmin     # cluster reads, exec, scale, approved Secret deletion
export CTX_ENG=griddle-platform-ccip-stage-teamccipengineer # secret creation (create, not patch)
export NS=chainlink-ccv

CCV=~/dev/dev2/chainlink-ccv
CLD=~/dev/dev2/chainlink-deployments
DEPLOY=~/dev/dev2/chainlink-ccv-deploy
EVM_VALUES=$DEPLOY/deploy/config/staging/committee-verifier-evm/config.yaml

# The chainlink-ccv commit the deployed images were built from (P2). Steps 2 and 3 run the
# migrate tooling from a worktree at this commit, so it matches what the pods run.
IMAGE_SHA=45c7148eaaa84fe6cc73f9baa4de12612971c665
CCV_IMG=/tmp/ccv-image

# per cutover; i = 0..20
i=1
NODE=chainlink-ccv-staging-$i               # JD alias, topology alias
CL=chainlink-ccv-$i                         # the node's k8s deployment, service, secret prefix
VER=committee-verifier-evm-$i               # verifier: release = Deployment (JD record keeps $NODE)
EXE=executor-evm-$i                         # executor: release = Deployment = JD node name
EXPECTED_ID=<from P8>                       # this node's OnchainSigningAddress from JD
```

Standalone names carry the chain family, following `committee-verifier-canton-0` in
chainlink-ccv-deploy and `committee-verifier-solana-0` / `executor-solana-0` in
chainlink-ccv-non-evm-deploy; other families will share this cluster and namespace. For the
executor, the griddle release name, the chart's `name` value (which becomes the Deployment name),
and the JD node name are the same string. The verifier shares the first two, but its JD record
keeps the node's alias (`$NODE`), because it adopts the CL node's record in step 7.

The alias-to-node mapping (`chainlink-ccv-staging-$i` to `chainlink-ccv-$i`) is assumed 1:1 by
index. The export in step 3 verifies it for free: `--expected-id` carries the alias's JD signing
address, and the export fails if the node behind the port-forward holds a different key.

Deploys are IssueOps: branch in chainlink-ccv-deploy, open a PR (ready, not draft), comment
`.deploy stage` on it, thumbs-up the confirmation comment. There is no auto-deploy on merge, and
the `.deploy` comment deploys every instance in the env, rendered from the branch. Merge main into
the branch first: a branch behind main rolls back whatever main changed since, other teams'
releases included. `.noop stage` shows the rendered diff without pushing. `gcli deploy render -e
stage` and `gcli helm template -e stage -N <instance> -c griddle.yaml` preview locally.

Pipeline runs in chainlink-deployments are either local
(`go run ./domains/ccv/cmd durable-pipeline run --environment staging_testnet --input-file
<name>.yaml`, with `--dry-run` first) or the canonical path: commit the input YAML under
`domains/ccv/staging_testnet/durable_pipelines/inputs/`, open a PR, comment `/run-pipelines`.
Either way the run performs real JD and on-chain operations.

## Prerequisites (before the first node migrates)

### P0. Access, pipelines, and JD auth

Three checks, all before the first node.

Secrets. P6 and step 4 create secrets through `$CTX_ENG`. The engineer role can create secrets
but not patch them (chainlink-ccv-deploy,
`deploy/config/staging/committee-verifier-canton/README.md`, "RBAC: create, not patch"). Confirm
the create permission before the day:

```sh
kubectl --context $CTX_ENG -n $NS auth can-i create secrets     # must print yes
```

If it prints `no`, that is an Okta access request, not a kubectl problem: namespace access is
granted through Okta groups, team `ccip`, role `TeamCCIPEngineer` or `TeamCCIPAdmin`
(chainlink-ccv-deploy `AGENTS.md`, "Accessing the Platform"). Ask makramkd which request to file.

Pipelines. staging_testnet already registers the shared CCV pipelines (`apply-verifier-config`,
`apply-executor-config`, `jd_*`), unlike staging-migration, so no code change is needed. The
cutover uses `jd_update_nodes` and `jd_register_nodes` in step 7, and `apply-verifier-config` and
`jd_propose_job` in step 9:

```sh
cd $CLD
go run ./domains/ccv/cmd durable-pipeline list --environment staging_testnet
```

JD auth. The canonical pipeline path (commit the input, `/run-pipelines`) needs nothing here: CI
reads the ccv domain's JD credentials from its secret env vars
(`OFFCHAIN_JD_AUTH_COGNITO_APP_CLIENT_ID_CCV_STAGING_TESTNET` and its four siblings; the
`Secrets - Check Env Vars` workflow in chainlink-deployments reports whether they are set). Local
runs (`durable-pipeline run`, `jd node ...`) need the same five values in
`domains/ccv/.config/local/config.staging_testnet.yaml`, which does not exist today. The
scaffold command is in the `cmd/cld` module, not the domain CLI:

```sh
cd $CLD/cmd/cld
go run . domain config local create --domain ccv --env staging_testnet
```

Then fill in `offchain.job_distributor` (field reference:
`docs/docs/guides/configuration/environment/reference.md` in chainlink-deployments):

```yaml
offchain:
  job_distributor:
    endpoints:
      grpc: grpc-job-distributor.main.stage.cldev.sh   # as in .config/ci/staging_testnet.env
    auth:
      cognito_app_client_id: ...
      cognito_app_client_secret: ...
      aws_region: ...
      username: ...
      password: ...
```

Where the values come from: the staging JD is shared across domains, and its Cognito app client
and service user are provisioned on the CLD side. The CLD docs (`job-distributor/introduction.md`
and `ci-cd/environment-variables.md` under `docs/docs/guides/`) only describe the CI path, where
changes go through the secret env var workflows and need CLD team approval in
`#cld-guardian-support`. There is no self-serve path for a local copy: ask in
that channel for the ccv `staging_testnet` set, or skip local runs and use `/run-pipelines`
throughout. Every JD action in the cutover has a pipeline form, so nothing below needs the local
file. The local file is gitignored; never commit it.

### P1. Consolidate verifier jobs (run while still in CL mode)

Two aggregators means each node runs two `ccvcommitteeverifier` jobs for the default committee
today; standalone runs one. Aggregator HMAC creds keep working: legacy `verifier_id`s become
`secret_name`s.

Consolidate in explicit `targetNops` batches of at most three nodes. Each chain has 10 default
committee members with threshold 6, so no batch can take enough verifiers offline to lose quorum.
Replace the example names with the current batch, and never run this input unscoped.

```sh
cat > $CLD/domains/ccv/staging_testnet/durable_pipelines/inputs/evm_consolidate_verifier_jobs.yaml <<'EOF'
environment: staging_testnet
domain: ccv
changesets:
  - apply-verifier-config:
      payload:
        committeeQualifier: "default"
        defaultExecutorQualifier: "default"
        chainFamily: evm
        consolidateAggregators: true
        revokeOrphanedJobs: false
        targetNops: ["chainlink-ccv-staging-1", "chainlink-ccv-staging-2", "chainlink-ccv-staging-3"]
EOF
cd $CLD
go run ./domains/ccv/cmd durable-pipeline run --environment staging_testnet \
  --input-file evm_consolidate_verifier_jobs.yaml --dry-run
# then without --dry-run, or commit + /run-pipelines
```

Keep `revokeOrphanedJobs: false`. The payload spelling otherwise matches the Solana consolidation
on 2026-10-30 (`durable_pipelines/archived/solana_consolidate_verifier_jobs_20261030_005630.yaml`).
Before P1, the EVM DON runs one job per aggregator; P1 replaces those with the consolidated default
job while leaving the inactive secondary records alone.

What P1 does to the 21 CL nodes, beyond the job count:

- Each node gets a new job proposal and holds it until someone approves it in the node's Feeds
  Manager tab (operator UI, through step 3's port-forward). CL nodes only auto-approve workflow
  specs.
- The per-aggregator jobs keep running. A CL node only revokes pending specs, and JD refused
  all four approved jobs in the Solana run (`job cannot be revoked`). With revocation enabled, the
  changeset can log that failure and drop the jobs from the datastore anyway, losing information
  later steps need. Cancel each node's two old proposals in Feeds Manager instead, which deletes
  the jobs and tells JD (`chainlink jobs delete` refuses a feeds-manager job). Approve first, then
  cancel: the aggregators drop duplicate signatures (`ON CONFLICT ... DO NOTHING`), while
  cancelling first stops the node signing until the approval. Finish and verify every node in the
  batch before starting another.
- The consolidated job has a new `verifier_id` (`default-verifier` instead of
  `<aggregator>-default-verifier`), and chain status is keyed by `verifier_id`. The new job starts
  with no chain-status rows: no checkpoint and no disabled flags. It scans from 500 blocks behind
  the finalized head, and a chain disabled under the old IDs comes back enabled. Before P1, run
  the step 1 chain-status listing on every node. If any row is disabled, re-apply it for
  `default-verifier` after P1 (`chainlink node ccv chain-statuses disable`; the change takes
  effect on the node's next start, so stop the node first).
- Hard rule 6 starts here: every later EVM `apply-verifier-config` input sets
  `consolidateAggregators: true` and keeps `revokeOrphanedJobs: false`, step 9 included.

Node 0 is also the sole member of the `secondary` committee
(`[nop_topology.committees.secondary]` in `domains/ccv/staging_testnet/topology.toml`). Its secondary
records are stale: there is no live secondary job in Feeds Manager and no secondary-aggregator
service. There is nothing to migrate or clean up. Do not deploy a second standalone verifier and do
not change the secondary onchain contracts. Node 0 uses only its live default verifier and executor
in the final wave.

### P2. Images

No manual build. Every merge to main runs `build-push-main.yaml` in chainlink-ccv, which builds
the verifier, aggregator, indexer, and executor images for that commit and publishes them as
`containers/chainlink-ccv-<module>:<sha>-rc` (full 40-char commit SHA) to the primary and
secondary private ECRs. The staging aggregator and indexer values already pin images this way.

The staging values pin `$IMAGE_SHA-rc` (main at #1577) for both processes. That build includes
chain-setting parity (carried node settings and the embedded chain defaults); an older image runs
gas, node-pool and head-tracker settings that differ from the CL node's. A later bump has to name a
real main commit: a short SHA padded out to 40 characters names an image that was never built.
Both standalone components deploy at `replicas: 0` in P7, so no pod proves the image until the
cutover starts. Check the image directly before approving the wave's start PR; the verifier image
comes from the same workflow run:

```sh
aws ecr describe-images --region us-west-2 --registry-id 809128755817 \
  --repository-name containers/chainlink-ccv-verifier --image-ids imageTag=$IMAGE_SHA-rc
```

Then create the worktree steps 2 and 3 run the migrate tooling from:

```sh
git -C $CCV fetch origin && git -C $CCV worktree add --detach $CCV_IMG $IMAGE_SHA
```

A release tag is the alternative: release-please cuts the root `vX.Y.Z` tag and
`release-publish.yaml` publishes the same images tagged `vX.Y.Z`, no `-rc`. Prod-testnet uses that
path. `manual-build.yaml` (tag `manual-<ref>-rc`, primary ECR only) is for testing an unmerged ref
and is not part of this plan.

### P3. Charts and config dirs

Both charts exist in chainlink-ccv-deploy and are shared with the Solana and Canton releases:
`committee-verifier-base` (v0.1.6) for the verifiers and `executor-base` (v0.1.1, from #456) for
the executors. Neither chart has anything EVM-specific; the values carry the image, ports,
configs, and mounts. The existing `push-helm-charts.yaml` workflow publishes both.

Both processes take their file locations from env vars (`BOOTSTRAPPER_CONFIG_PATH`,
`EVM_CONFIG_PATH`, `BOOTSTRAPPER_SECRETS_PATH`, `COMMITTEE_VERIFIER_SECRETS_PATH`;
`bootstrap/bootstrap.go`, `integration/pkg/accessors/evmconfig/config.go`,
`verifier/pkg/vsecrets/vsecrets.go` in chainlink-ccv). On top of those, the values set:

- Probes on the bootstrap info server: `/health` on `[server].listen_port` (9988). The app server
  (8100 verifier, 8101 executor) only starts once JD proposes a job in step 9, so probing it would
  kill the pods before then. The info server itself starts only after the DB migrations, keystore
  setup (including the key import), and the JD lifecycle start, which also starts a cached job
  synchronously on a restart (`startWithJDLifecycle`). A `startupProbe` (30 × 5s) covers that boot
  before liveness takes over. Bootstrap `/health` is a static 200; after step 9 the real signal
  is the app server's `/health`.
- `strategy: Recreate`. A rolling update starts the new pod before the old one stops, which for a
  short window would run two verifiers on one signing key and CSA identity, or two executors
  racing on one transmitter key's nonces.
- No PodDisruptionBudget (with one replica, `minAvailable: 1` blocks every node drain) and no
  ServiceMonitor (neither port serves `/metrics`; metrics go out through Beholder and the OTEL
  sidecar).
- A `[key_import]` block, rendered into the shared bootstrap `config.toml` from each verifier
  instance's `keyImport.expectedId` (P8's address). Every verifier carries the block from its first
  deploy, so none can come up with a self-generated key: until step 4 mounts the export, the
  import fails and the boot stops. That makes hard rule 3 a property of the config. The block
  stays after the cutover: once the key is in the keystore the import is skipped, but
  `expected_id` is still checked against it on every boot.
- The admin console (`adminConsole`, new in `committee-verifier-base` v0.1.6). The verifier serves
  this recovery UI in-process while its job runs, and only when `/etc/ccv-admin/config.toml`
  exists, which the chart mounts from a ConfigMap. The config is
  `listen_address = "127.0.0.1:8105"`: on loopback the console needs no `[admin_ui]` credentials
  and only answers `localhost` requests, so the way in is a port-forward (see Validation), and the
  chart adds no Service port or route. The console decodes its config strictly, and a config it
  rejects makes the verifier's job fail to start, so check any change with
  `verifier ccv admin check-config` from the same image.

Config dirs, one per family chart, named like the releases (scaffolded for node 1):

- `deploy/config/staging/committee-verifier-evm/`: `common.yaml` (image, probes, strategy,
  resources, labels, sidecar, admin console), `config.yaml` (non-secret `configs:` TOMLs),
  `committee-verifier-evm-$i.yaml` (`name`, `keyImport.expectedId`, `replicas`, the secret
  volumes).
- `deploy/config/staging/executor-evm/`: the same three, without `keyImport`.

### P4. Databases (3 per node, on the node's own cluster)

Verifier-bootstrap, verifier-app, executor-bootstrap. They cannot share a database (both migration
runners use goose's default version table). Each node's three go on an Aurora cluster of its own,
`chainlink-ccv-evm-standalone-$i`: 21 clusters and 63 databases if the whole committee migrates.
Provision at least the next node's cluster and databases before its window.

Not on `chainlink-ccv-dons`, which hosts the 21 CL node databases. The standalone processes
cannot load the DON cluster, and if a standalone database has to be dropped, or a node's cluster
wiped after a bad cutover, nothing CL-mode is on it, so the rollback path (scale the CL node back
up, repoint its CSA key) never depends on the new clusters.

Not on one cluster shared by every migrated node either. Each chain config has 10 members and
threshold 6, so once five of a chain's members share a cluster, one failover or saturated
instance stalls attestations on that chain. With a cluster per node the same incident costs one
signer, which is how a database failure lands for a NOP running its own. Per-node clusters also
keep one verifier's backlog catch-up or source-range replay from taking CPU or connections from
the rest (each verifier opens up to 20 app-database connections), and they keep database changes
on the cutover cadence: a resize, engine upgrade, or wipe touches one node at a time.

Both live in `$DEPLOY/deploy/config/staging/database-provisioner/database-provisioner.yaml`. Node
1's cluster:

```yaml
databaseClusters:
  chainlink-ccv-evm-standalone-1:
    engine: aurora-postgresql
    engineVersion: "17.5"
    deletionProtection: true
    instances:
      count: 1
      instanceClass: db.t4g.medium
```

One `db.t4g.medium` is the shape of the Canton and Solana verifier clusters in the same file.
A single instance has no failover target, which is acceptable when its outage costs one signer.
Revisit the class after the first soak. Backups default to 7 days (the chart reads
`backupRetentionPeriod`; the `backupRetentionDays` key on `chainlink-ccv-dons` is ignored). Add
each node's cluster in the same PR as its databases and confirm it is ready before expecting
connection secrets.

No fourth database for staging. The standalone LogPoller reader stays off here (open question 4),
and it is what would need one: its `evm` schema (LogPoller blocks plus 30 days of
`CCIPMessageSent` logs per OnRamp) goes in the database named by `[db].url` in the EVM secrets
file, which can be the app database or its own. Those tables are forward-only migrations like the
rest, so never point an older image at a database a newer one has migrated. See
[Source logs](../verifier/evm-standalone.md#source-logs-rpc-or-a-logpoller).

`deletionProtection: true` is enforced by Gatekeeper (`prevent-xr-deletion-protection`). Wiping
a node's cluster after a bad cutover first takes a deploy that sets it to `false`; a delete
attempted before that is denied and can leave the release stuck uninstalling.

Database map keys must stay at or under 43 chars (the composition appends `-provider-sql-config`
and the result is a 63-char k8s label). Set `connectionSecret.name` explicitly. Node 1's block, as
the model:

```yaml
databases:
  ccv-evm-1-verifier-bootstrap:
    databaseClusterName: chainlink-ccv-evm-standalone-1
    databaseName: ccv_evm_1_verifier_bootstrap
    connectionSecret:
      name: ccv-evm-1-verifier-bootstrap-database-connection
  ccv-evm-1-verifier-app:
    databaseClusterName: chainlink-ccv-evm-standalone-1
    databaseName: ccv_evm_1_verifier_app
    connectionSecret:
      name: ccv-evm-1-verifier-app-database-connection
  ccv-evm-1-executor-bootstrap:
    databaseClusterName: chainlink-ccv-evm-standalone-1
    databaseName: ccv_evm_1_executor_bootstrap
    connectionSecret:
      name: ccv-evm-1-executor-bootstrap-database-connection
```

Deploy (PR + `.deploy stage`), then verify:

```sh
kubectl --context $CTX -n $NS get databasecluster chainlink-ccv-evm-standalone-$i
kubectl --context $CTX -n $NS get secret ccv-evm-$i-verifier-app-database-connection
```

Each connection secret carries `POSTGRES_HOST/PORT/USER/PASSWORD/DB`.

### P5. Per-chain txm_block_time (completed)

Running `ccv migrate inspect-config` against the staging node EVM config
(`deploy/config/staging/chainlink-ccv/rpcs.yaml` + `chains.yaml`) and the extracted standalone
`evm-config.toml` (`deploy/config/staging/committee-verifier-evm/config.yaml`) produces zero
`failed_chains` and the following effective settings for the five staging committee chains:

| Chain | Selector | Chain ID | `finality_depth` | `finality_tag_enabled` | `txm_block_time` | `txm_block_time_source` | RPCs (WS) |
|---|---|---|---|---|---|---|---|
| `ethereum-testnet-sepolia` | `16015286601757825753` | `11155111` | `50` | `true` | `12s` | `curated_chain_default` | 3 (all WS) |
| `ethereum-testnet-sepolia-arbitrum-1` | `3478487238524512106` | `421614` | `50` | `true` | `2s` | `generic_fallback` | 3 (all WS) |
| `ethereum-testnet-sepolia-base-1` | `10344971235874465080` | `84532` | `200` | `true` | `2s` | `generic_fallback` | 2 (all WS) |
| `polygon-testnet-amoy` | `16281711391670634445` | `80002` | `500` | `true` | `2s` | `generic_fallback` | 2 (all WS) |
| `avalanche-testnet-fuji` | `14767482510784806043` | `43113` | `1` | `true` | `2s` | `generic_fallback` | 2 (all WS) |

No manual `Transactions.TransactionManagerV2.BlockTime` overrides are needed in the staging
`evm-config.toml`: Ethereum Sepolia receives `12s` from `curatedTXMBlockTimeByChainID` (PR #1461),
and upstream `chainlink-evm` rejects `BlockTime < 2s` (`DefaultTXMBlockTime = 2 * time.Second`),
so `2s` is already the minimum legal value for Arbitrum Sepolia, Base Sepolia, Polygon Amoy, and
Avalanche Fuji. Verified again in cutover step 2 with `inspect-config`.

### P6. Secrets per node

Two runtime secrets per node before its window and a third during it, all created by hand through
`$CTX_ENG` and never committed. The names are the ones the node's values files mount. Prepare each
node just in time and delete each local TOML immediately after its runtime Secret create succeeds.

| Secret | Key | Holds | Must exist before |
|---|---|---|---|
| `$EXE-secrets-v2` | `bootstrap-secrets.toml` | executor bootstrap `[db].url`, `[keystore].password` | step 6 |
| `$VER-secrets-v2` | `bootstrap-secrets.toml` | verifier bootstrap `[db].url`, `[keystore].password` | step 6 |
| `$VER-secrets-v2` | `verifier-secrets.toml` | verifier app `[db].url`, one `[[aggregators]]` HMAC pair per aggregator | step 6 |
| `$VER-keyimport-v1` | `key.json`, `export-password.txt` | the step 3 export | created in step 4 |

Schemas: `docs/config/bootstrap/secrets.documented.toml` and
`docs/config/verifier/secrets.documented.toml` in chainlink-ccv. Compose the DB URLs from the P4
connection secrets:

```sh
db_url() { kubectl --context $CTX -n $NS get secret "$1" -o go-template='postgres://{{index .data "POSTGRES_USER" | base64decode}}:{{index .data "POSTGRES_PASSWORD" | base64decode}}@{{index .data "POSTGRES_HOST" | base64decode}}:{{index .data "POSTGRES_PORT" | base64decode}}/{{index .data "POSTGRES_DB" | base64decode}}'; }
db_url ccv-evm-$i-verifier-bootstrap-database-connection
```

Give each process its own keystore password (`openssl rand -hex 32`). The keystore holds the
process's CSA key, the verifier's imported signing key, and the executor's funded transmitter key,
so keep a copy of each password outside the cluster in a secret store (for example macOS Keychain),
not in terminal output or an unencrypted worktree.

```toml
# /tmp/$EXE-bootstrap-secrets.toml. /tmp/$VER-bootstrap-secrets.toml has the same shape, with the
# verifier bootstrap database and its own password.
[db]
url = "<db_url ccv-evm-$i-executor-bootstrap-database-connection>"

[keystore]
password = "<openssl rand -hex 32>"
```

```toml
# /tmp/$VER-app-secrets.toml
[db]
url = "<db_url ccv-evm-$i-verifier-app-database-connection>"

[[aggregators]]
secret_name = "aggregator-1-default-verifier"
api_key = "<APIKey>"
secret_key = "<APISecret>"

[[aggregators]]
secret_name = "aggregator-2-default-verifier"
api_key = "<APIKey>"
secret_key = "<APISecret>"
```

The HMAC pairs are the ones the CL node signs with today: the `[[CCV.AggregatorSecrets]]` entries
in the node's own secrets file, key `user-secret.toml` of the `$CL-usr-v3` secret. Each entry's
`VerifierID` is the `secret_name` (P1's consolidated job reuses the per-aggregator verifier IDs),
`APIKey` is `api_key`, and `APISecret` is `secret_key`. The aggregators already accept these
pairs, so nothing changes on their side. The same file holds the node's database URL and keystore
password, so write it to a private file instead of the terminal:

```sh
umask 077
kubectl --context $CTX -n $NS get secret $CL-usr-v3 \
  -o go-template='{{index .data "user-secret.toml" | base64decode}}' > /tmp/$CL-user-secret.toml
```

Create versioned secrets named after the instance (create-not-patch RBAC; a later replacement means
`-v3` plus a values repoint, per the canton README workflow), then delete the `/tmp` files:

```sh
kubectl --context $CTX_ENG -n $NS create secret generic $EXE-secrets-v2 \
  --from-file=bootstrap-secrets.toml=/tmp/$EXE-bootstrap-secrets.toml &&
kubectl --context $CTX_ENG -n $NS create secret generic $VER-secrets-v2 \
  --from-file=bootstrap-secrets.toml=/tmp/$VER-bootstrap-secrets.toml \
  --from-file=verifier-secrets.toml=/tmp/$VER-app-secrets.toml &&
rm -- /tmp/$EXE-bootstrap-secrets.toml /tmp/$VER-bootstrap-secrets.toml \
  /tmp/$VER-app-secrets.toml /tmp/$CL-user-secret.toml
```

Delete these files as soon as both Secret creates succeed; do not leave them for step 11. In
particular, the verifier bootstrap TOML contains the password that unlocks the active signing key.

Nothing else here is secret. There is no EVM secrets file (`EVM_SECRETS_PATH`, default
`/etc/evm/secrets.toml`): it holds the standalone LogPoller's `[db].url` and is only read when a
chain turns that reader on, which staging does not. The staging verifier jobs set no
`[policy_hook]`, the admin console on loopback needs no `[admin_ui]` credentials, the executor
reads the indexer over plain HTTP, and the CSA keys that authenticate to JD are generated at
first boot.

### P7. Griddle releases, both components at zero replicas

Two entries per node in `$DEPLOY/griddle.yaml` under the stage env, after the Solana entries. Add
them per wave or prepare all remaining nodes at once. `ccip_env: stage` matches the rest of the
file, though the image-sync check only requires it for the aggregator, indexer, chainlink-ccv,
infra, and token-verifier releases. Shape:

```yaml
    - name: committee-verifier-evm-1
      namespace: chainlink-ccv
      path: deploy/charts/committee-verifier-base
      ccip_env: stage
      config:
        - deploy/config/staging/committee-verifier-evm/common.yaml
        - deploy/config/staging/committee-verifier-evm/config.yaml
        - deploy/config/staging/committee-verifier-evm/committee-verifier-evm-1.yaml
      settings:
        install_timeout: 5m0s
        rollback_timeout: 5m0s
        upgrade_timeout: 5m0s
    - name: executor-evm-1
      namespace: chainlink-ccv
      path: deploy/charts/executor-base
      ccip_env: stage
      config:
        - deploy/config/staging/executor-evm/common.yaml
        - deploy/config/staging/executor-evm/config.yaml
        - deploy/config/staging/executor-evm/executor-evm-1.yaml
      settings:
        install_timeout: 5m0s
        rollback_timeout: 5m0s
        upgrade_timeout: 5m0s
```

Set `replicas: 0` for **both** the verifier and executor in the infrastructure-prep PR. This keeps
their Deployment objects present without starting either process. Runtime secrets are required before
the cutover start PR, not before the zero-replica infrastructure deploy. Each verifier also carries
`keyImport.expectedId` and the key-import volume/mounts so the cutover can change only replica counts
and `maintenanceMode`. The database-provisioner's `upgrade_timeout` is `30m0s` because SQL role,
database, and grant creation can outlast the default five minutes and then recover on retry. Preview
before deploying:

```sh
cd $DEPLOY && gcli helm template -e stage -N committee-verifier-evm-1 -c griddle.yaml
# or without gcli: python3 scripts/griddle_template.py -e stage -N committee-verifier-evm-1 --dry-run
```

### P8. expected_id per node, from JD (pre-extracted)

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json
go run ./domains/ccv/cmd validate nop-support -e staging_testnet
```

Record each node's `OnchainSigningAddress`; that value is `$EXPECTED_ID` in step 3 and the
verifier instance's `keyImport.expectedId`. While here, also record each node's current CSA key:
the rollback path needs it (step 7). Without local JD credentials, the same address is the
`signer_address` in the node's current verifier job spec in the datastore:

```sh
jq -r --arg n "$NODE" '.metadata.offchainConfigs.nopJobs[$n] | to_entries[]
  | select(.key|endswith("verifier")) | "\(.key): \(.value.spec | capture("signer_address = \"(?<s>[^\"]+)\"").s)"' \
  $CLD/domains/ccv/staging_testnet/datastore/env_metadata.json
```

Re-check the value for each node right before its window.

Pre-extracted from `domains/ccv/staging_testnet/state_v2.json` and `topology.toml` (all 21 nodes are in `executor_pools.default` on all 5 EVM chains; the `default` committee memberships per node are listed in the last column):

| `i` | `NODE` (`chainlink-ccv-staging-$i`) | JD `nodeID` | `EXPECTED_ID` (`OnchainSigningAddress`) | Current `csaKey` (for rollback) | `default` Committee Chains |
|---|---|---|---|---|---|
| `0` | `chainlink-ccv-staging-0` | `node_tSJyxmzinkkBCTBmmWEif` | `0xf5a79545c47626e887c997947bc151dd8e1cd119` | `be7b515dcba8644713ef97b2d13d14a8bb9bd82dae57166db29c406e4e2baa51` | sepolia, base-sepolia, fuji (+ stale `secondary` config on all 5; no live job) |
| `1` | `chainlink-ccv-staging-1` | `node_i2JZrhxmAg8K9fW5Gvc3p` | `0x7a73ab91f326ff363a809a0a1f2fca775a7b833a` | `90f6e2c9ff28bac3842795ba8e9376e8ab5caa22f3e2614de7525c06a9df3fa1` | sepolia, base-sepolia, fuji |
| `2` | `chainlink-ccv-staging-2` | `node_ETjCLpmUnUZVCmbR5x2Bs` | `0xd560730b7cc1b0121285d8f00e65be7094e185e5` | `79ff7e4178d64f6e7a87f5b7d9df27b6e90dcada6a0c5c33cdf422a3521005dd` | sepolia, amoy, fuji |
| `3` | `chainlink-ccv-staging-3` | `node_12Rgtg5jTpyodhKhqyKcQ` | `0x5f9788949ed8c6bc0aab30a23d7b987047ff2f01` | `ba310e8dee96fd13fc07d00d189262d5eb15b084bf87d1ec78aadbad0f679cd5` | sepolia, amoy, fuji |
| `4` | `chainlink-ccv-staging-4` | `node_H9h8C4BXwAkfcUBZ82Zn2` | `0x0fde5b6082f90e2e43a3111618a5cdd24b045d02` | `c05c438d738afac0f41bd52fd47618b66260272507fa9e51631473f09de9a8d9` | sepolia, amoy, fuji |
| `5` | `chainlink-ccv-staging-5` | `node_PbkLq7oDW2gXNUJ6ZmQhr` | `0x6e301a383c68898faf4b7a66dca11df9a8db2f48` | `13b8a0e40303ff9730b185da4c17db4bd85f374a0ce4855613ce595704bc8cf7` | sepolia, arb-sepolia, base-sepolia |
| `6` | `chainlink-ccv-staging-6` | `node_sZCxytw5BNe7yMKtXiZkW` | `0xb07c183e24a056cbfb1b42fddf5bd2f537f752db` | `11fde00c137fba8c192fcbb8442825eaee9abca05ad5b896380007eaa337c928` | sepolia, arb-sepolia, base-sepolia |
| `7` | `chainlink-ccv-staging-7` | `node_bo7KWbwnLZJLQaaxMwjeN` | `0xdb9cf3fcb9bdedc8783894bf8d9d8e0ec641342e` | `149444e8e9b1dbcc81e8d0f10bfa92ecd1e7a5b8c4322dff62f17ca6179f6004` | sepolia, arb-sepolia, amoy |
| `8` | `chainlink-ccv-staging-8` | `node_MAmH6ecGvEwsGCDEG5rSZ` | `0x418a72c5c5789188bf526ac978fe9faccc4a7d61` | `15b622172dd092303a8ed00403789fa62f8561abf70448d00cabca3bb44e3bd3` | sepolia, arb-sepolia, amoy |
| `9` | `chainlink-ccv-staging-9` | `node_ixwrvUY91DULFurjJFJFN` | `0x1da76d603c752235b191054190078c433408f20b` | `fc34178bc16262904ff142db15eed49ef782e8bbee2182c00f11eb5e034aa2cb` | sepolia, arb-sepolia |
| `10` | `chainlink-ccv-staging-10` | `node_fjAxw3eskCXpdQGe7RRkV` | `0xe49c91674c67cb8506c2a7df4bd23c91d3ebdfdf` | `39d25a0b83fe4a3771c958be40bfe4905bd8e822aac82c6a2175d0e2e0fc404d` | arb-sepolia, base-sepolia, fuji |
| `11` | `chainlink-ccv-staging-11` | `node_goPAVmZXSJdVdbyBTqujA` | `0x765f5b1ac1ef78772dff5c2aa25454336f1d3058` | `49cf72eec5631e17b25d0123495c25fbde1197b8ea883b877856afe4d72f4c51` | arb-sepolia, amoy, fuji |
| `12` | `chainlink-ccv-staging-12` | `node_WoAUC8EasVzywE5yqQoZ2` | `0x8c0c2b9ddad65ee50f3c5e30dd1566a85f5b5357` | `5367a745a1563d86f193532c3c879de000f2b6ee9e58059780a7e8e76b79e21f` | arb-sepolia, fuji |
| `13` | `chainlink-ccv-staging-13` | `node_aVVsNYYWqZxuKymkoFh4q` | `0x5a7e4c7ba296e37b9189aa81784f1919610e1c16` | `7469688cceade61d1b5b31b65b40360835dfe60aea24472abf55bd609d72d59e` | base-sepolia, fuji |
| `14` | `chainlink-ccv-staging-14` | `node_1b1PrckNBud1DdMmcp4uf` | `0x4e1527efd9de84526dae3b475e0cc5e7987b1d01` | `95cc2a5c471fc8eec930e0278cf57b8d94370e90928d6d62fb4780fd5f08d5fa` | base-sepolia, fuji |
| `15` | `chainlink-ccv-staging-15` | `node_UUkACpneCivMV1i7XtCkF` | `0xafe7b91825dbe7a0c41e5d711c0b2c4cbd20b481` | `3e4a344d80d61148dc234f30a64969f0164d5d6b41c5863dfc0dc0c3b28f0d78` | arb-sepolia, base-sepolia |
| `16` | `chainlink-ccv-staging-16` | `node_Ji7guBBXDWJ1Z6nBcJZAR` | `0xd5f84d3182d1e57de3fec12d3cce501f507d0e55` | `aeba5c8c6fcf68b3e03453371d3b713dd4813b906069b8e50c3487882883c977` | arb-sepolia, amoy |
| `17` | `chainlink-ccv-staging-17` | `node_dqhFHPxQfji1qydkkV671` | `0x80190830684043dda66193142d8594c712556c59` | `42f8c9d6c7d81bce5b670006cbb806c2f5d8a21561d5e36e80a21976bd061b9e` | base-sepolia, amoy |
| `18` | `chainlink-ccv-staging-18` | `node_dzjeC4mj574v14hfzBogy` | `0xa0211cd441274e37db292726fac6a19fb25f67b9` | `a62b9047b2d78c177348c23e47c8cde94bdd903114c2bee4d374bc66be0e4f4c` | base-sepolia |
| `19` | `chainlink-ccv-staging-19` | `node_yQ9bqxHQVrKSd1Cccd4ix` | `0x7b9f3303baad0b738cfb3251ce5d5ab2943fa386` | `378571a8feedfa8f7cbaccccf73111a74b108703e41656836be2dd2ed7f4c1bb` | amoy |
| `20` | `chainlink-ccv-staging-20` | `node_WxLBzEknoUfFpfhVLEfC4` | `0xa76ac8de1ab07dffd464284392d257bae5cabd62` | `e5671d6d8f89e627f2097acd42600352bcde28d99141867293c5f8d8865a101a` | amoy |

### P9. Funding source

Use the [Internal Faucets API](https://smartcontract-it.atlassian.net/wiki/spaces/dapp/pages/585924700/Internal+Faucets+API)
to top up the migration wallet. Request only the shortfall to **2.5 native tokens per chain**, using
the current UI's `activeNetwork` object and `nativeTokenToSend`; do not request LINK. Do not retry
failed or unsupported networks without investigating them, since faucet balances are limited.

Fund each new executor with **0.15 native token on each of the five staging EVM chains**. That is
0.75 per node and 2.25 for the 15-node final wave, plus funder gas. Verify every receipt and balance
before running the CLD input.

Balance alerts are out of scope for staging. The CL nodes have none today that this plan could
carry over: `[EVM.BalanceMonitor] Enabled = true` in
`deploy/config/staging/chainlink-ccv/chains.yaml` only exports the balance metric, and nothing in
chainlink-ccv-deploy defines an alert on it. The standalone executor does not run the balance
monitor at all, so an unfunded transmitter surfaces as failed broadcasts. The soak in step 12
therefore includes a manual balance check on the five testnets. Alerts are a prod item.

## The cutover, by wave

Apply steps 1–12 to each node in the wave. Use one deployment PR for replica counts and
`maintenanceMode`, and one combined CLD input for CSA handoff, verifier jobs, and executor jobs.
The combined input must be the only active file under `durable_pipelines/inputs`; archive or remove
completed wave inputs before running it.

### 1. Preflight

```sh
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink admin login --file /v2Secret/.api
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink jobs list
kubectl --context $CTX -n $NS exec deploy/$CL -- bash -c 'psql "$(sed -n "/^\[Database\]/,/^\[/p" /v2Secret/secret.toml | grep -E "^\s*URL\s*=" | sed -E "s/^\s*URL\s*=\s*\"([^\"]+)\".*/\1/")" -X -c "SELECT chain_selector, verifier_id, finalized_block_height, disabled FROM ccv_chain_statuses ORDER BY 1, 2"'
```

The chain statuses are read with `psql`, using the DB URL extraction from the chart's init container.
`chainlink node ccv chain-statuses list` does not work here: like every local `chainlink node`
command it takes the database lease, which the running node holds, so it waits forever.

`/v2Secret/.api` is inside the node container. The `chainlink-cluster` chart mounts the node's
`$CL-v2` secret at `/v2Secret` and starts the node with `-a /v2Secret/.api`
(`deploy/charts/chainlink-cluster/templates/common/deployment.yaml`, the `$arguments` line; the
key name is `chainlinkNode.spec.credentials.config.api.key`, `.api` by default), so
`admin login --file` reads the credentials file the node itself booted with. Step 3 pulls the
same key out of the secret for the port-forward path.

Expect exactly one `ccvcommitteeverifier` job (post-P1; node 0 is the exception, see open
question 1) and one `ccvexecutor` job. Record any chain-status row with `disabled = true`; step 10
needs the selectors.

### 2. Diff the config

Diff the EVM config the standalone pods mount, which is the `evm-config.toml` extracted from the
node's config into the deploy values. Run the conversion from the image-commit worktree (P2), so
the diff is exactly what the pods will run:

```sh
yq '.configs."evm-config.toml"' "$EVM_VALUES" > /tmp/evm-config.toml
cd $CCV_IMG
go run ./cmd/verifier/committee ccv migrate inspect-config --config /tmp/evm-config.toml
```

To compare against the node itself, run the same command on the node's effective TOML (render the
release with `gcli helm template -e stage -N chainlink-ccv -c griddle.yaml`, or read the live
ConfigMap); P5 found the two equivalent for all five chains.

Confirm `failed_chains` is empty and each of the five chains matches the P5 baseline (`12s` via
`curated_chain_default` on Ethereum Sepolia; `2s` floor via `generic_fallback` on Arbitrum Sepolia,
Base Sepolia, Polygon Amoy, and Avalanche Fuji).

### 3. Export the verifier key

```sh
kubectl --context $CTX -n $NS get secret $CL-v2 -o jsonpath='{.data.\.api}' | base64 -d > /tmp/api-creds.txt
kubectl --context $CTX -n $NS port-forward svc/$CL 6688:6688 &   # leave running
cd $CCV_IMG
go run ./cmd/verifier/committee ccv migrate export \
  --node-url http://localhost:6688 --api-creds /tmp/api-creds.txt \
  --out-dir /tmp/migration-$i --expected-id $EXPECTED_ID
```

Writes `ocr2.json`, `export-password.txt`, and `verifier.key_import.toml` (the `[key_import]`
block, address pre-filled) into `/tmp/migration-$i`. If the export fails on the expected-id check,
stop: either the wrong bundle or the wrong node is behind the port-forward. Do not retry with a
different value. A node with more than one EVM OCR2 bundle also needs `--bundle-id`; the
expected-id check still rejects any bundle but the registered one.

### 4. Create the key-import secret and prepare the start PR

```sh
kubectl --context $CTX_ENG -n $NS create secret generic $VER-keyimport-v1 \
  --from-file=key.json=/tmp/migration-$i/ocr2.json \
  --from-file=export-password.txt=/tmp/migration-$i/export-password.txt
```

The instance values already render the `[key_import]` block from `keyImport.expectedId` (P3).
Confirm they carry the address the export printed, rather than pasting the snippet anywhere:

```sh
grep expected_id /tmp/migration-$i/verifier.key_import.toml
grep -A1 '^keyImport:' $DEPLOY/deploy/config/staging/committee-verifier-evm/$VER.yaml   # same address
```

Then prepare (do not deploy yet) one chainlink-ccv-deploy PR for the wave that:

- keeps the `verifier-keyimport` volume and its two mounts from P7
  (`/etc/ccv/migration/key.json` and `/etc/ccv/migration/export-password.txt`);
- sets `replicas: 1` in both `$VER.yaml` and `$EXE.yaml`;
- adds every node index in the wave to `maintenanceMode.specificNodes` in
  `deploy/config/staging/chainlink-ccv/overrides.yaml`, retaining earlier waves' indices so no
  earlier CL node restarts.

Do not put `[key_import]` in `config.yaml`: every verifier instance shares that file.

### 5. Stop the CL nodes through the start PR

Comment `.deploy stage` on the start PR and confirm. `maintenanceMode` stops the selected CL nodes,
so no manual scale is required. The `chainlink-ccv` release applies before the standalone releases;
verify every selected Deployment is at zero and its pod is gone before the standalone pods start.
If you suspend the DON release for the window, resume it after validation so `maintenanceMode`
continues to hold those nodes at zero durably.

### 6. Check the standalone pair

No job exists yet, so the app ports (8100/8101) serve nothing and bootstrap `/ready` stays 503;
that is expected here. The images are distroless (no shell, no wget), so probe over a
port-forward with curl from your workstation.

```sh
kubectl --context $CTX -n $NS port-forward deploy/$VER 9988:9988 & PF=$!
sleep 2
curl -s http://localhost:9988/health   # verifier {"status":"ok"}
kill $PF
kubectl --context $CTX -n $NS port-forward deploy/$EXE 9988:9988 & PF=$!
sleep 2
curl -s http://localhost:9988/health   # executor
kill $PF
kubectl --context $CTX -n $NS logs deploy/$VER | grep -i expected_id     # must print nothing
```

### 7. CSA handoff

```sh
for R in $VER $EXE; do
  kubectl --context $CTX -n $NS port-forward deploy/$R 9988:9988 & PF=$!
  sleep 2
  curl -s -d '{"KeyNames":["bootstrap_default_csa_key"]}' \
    http://localhost:9988/keystore/reader/getkeys; echo
  kill $PF
done
# PublicKey in the response is base64; JD takes hex:
echo '<PublicKey>' | base64 -d | xxd -p -c 999
```

Repoint each node's existing JD record at its verifier's CSA key (this preserves the node ID and
alias), and register each executor as a new JD node named after its release, with a `target` label
step 9 uses to address it. The old CSA key and node ID are in the P8 table; rollback repoints the
record to the old key. Put both changesets at the start of the wave's one combined input:

```yaml
environment: staging_testnet
domain: ccv
merge-proposals: true
changesets:
  - jd_update_nodes:
      payload:
        nodes:
          - id: <node_id from P8>
            csa_key: "<verifier_csa_hex>"
          # one entry per verifier in the wave
  - jd_register_nodes:
      payload:
        domain: ccv
        nodes:
          - name: $EXE
            csa_key: "<executor_csa_hex>"
            is_bootstrap: false
            labels:
              target: $EXE
          # one entry per executor in the wave
```

Step 9 appends the verifier and executor changesets to this file. After approval, `/run-pipelines`
executes the indexed changesets sequentially (`max-parallel: 1`), so the CSA updates are visible to
the later verifier runs.

`jd_register_nodes` also writes `domains/ccv/staging_testnet/nodes.json` from JD. Confirm that file
actually lands in the PR. If the report says `was_registered: true` but the file is missing from the
pipeline commits, add the returned executor node IDs from the registration report and leave every
existing record unchanged. Do not rerun a successful pipeline just to regenerate it.

Then wait for both processes to dial in. Each logs `Connected to Job Distributor` once JD accepts
its key; a job proposed to a record whose owner has not dialed in sits unclaimed.

```sh
kubectl --context $CTX -n $NS logs deploy/$VER | grep 'Connected to Job Distributor'
kubectl --context $CTX -n $NS logs deploy/$EXE | grep 'Connected to Job Distributor'
```

With the P0 local config, `go run ./domains/ccv/cmd jd node list -e staging_testnet -f json` shows
the same thing, and `jd node update` / `jd node register` are the local forms of the two
pipelines (check `jd node update --help` for the `-k` spelling, which differs between framework
versions).

### 8. Fund the executor

```sh
kubectl --context $CTX -n $NS logs deploy/$EXE | grep evm/tx/executor_evm_transmitter_key
# or via the bootstrapper info server on :9988:
# curl -s -d '{"KeyNames":["evm/tx/executor_evm_transmitter_key"]}' http://localhost:9988/keystore/reader/getaddresses
```

The line is `key created` (or `key already exists` on a restart) and the address is in the
`evmAddress` field; it is emitted at process start. Fund it on all five testnets from the P9
source, for example:

```sh
for RPC in $RPC_SEPOLIA $RPC_ARB_SEPOLIA $RPC_BASE_SEPOLIA $RPC_AMOY $RPC_FUJI; do
  cast send <evmAddress> --value 0.15ether --rpc-url $RPC --private-key $FUNDER_KEY
done
```

Record the address in the cutover notes; the balance check in step 12 uses it. The old per-chain
transmitter balances stay put: they are testnet tokens and the rollback path, so nothing gets
swept in staging.

### 9. Flip the mode and propose both jobs

Append the mode to the node's block in `domains/ccv/staging_testnet/topology.toml`, as the canton
and solana entries in the same file already do:

```toml
[[nop_topology.nops]]
alias = "chainlink-ccv-staging-1"
name = "chainlink-ccv-staging-1"
mode = "standalone"
```

The verifier jobs come from `apply-verifier-config`, one changeset per node in the wave. With the
mode flipped it emits the standalone job shape and proposes to the record named `$NODE`, which step 7
handed to the standalone verifier. Append these to the combined input after the CSA changesets, then
append one `jd_propose_job` per executor for the exact-spec compatibility path used in staging. Do
not create separate verifier, executor, or CSA input files for the wave.

With tooling including #1590, a later executor update can use `apply-executor-config` after the
NOP declares `executor_node_name = "$EXE"` (or supplies the executor node ID) and that registration
is in the environment node list. This is also an alternative initial-delivery path when the
registration is already persisted. Do not run it without that routing metadata; the alias now
belongs to the verifier. On either path, compare the spec before delivery and require the existing
job name, `externalJobID`, `executor_id`, and intended executor-pool membership.

```yaml
# One changeset per verifier after the two CSA changesets:
  - apply-verifier-config:
      payload:
        committeeQualifier: "default"
        defaultExecutorQualifier: "default"
        chainFamily: evm
        consolidateAggregators: true
        revokeOrphanedJobs: false
        targetNops: ["$NODE"]

# One changeset per executor after all verifier changesets:
  - jd_propose_job:
      payload:
        domain: ccv
        jobspec_path: domains/ccv/staging_testnet/inputs/jobspecs/$EXE.toml
        node_labels:
          target: $EXE
```

After the run, check every generated verifier job against P8 before validating the wave. The
changeset reads the signer from what the verifier published to JD and writes it into the job:

```sh
jq -r --arg n "$NODE" '.metadata.offchainConfigs.nopJobs[$n][$n + "-default-verifier"].spec' \
  $CLD/domains/ccv/staging_testnet/datastore/env_metadata.json | grep signer_address   # must be $EXPECTED_ID
```

For a `/run-pipelines` run, read the same spec from the run's `*_datastore.json` artifact under
`domains/ccv/staging_testnet/artifacts/durable_pipelines/apply-verifier-config/`.

The executor job is the node's existing one, retargeted. Take its spec from the datastore and
change only the envelope field, `executorConfig` to `appConfig`; the job name, the
`externalJobID`, and the config stay as they are, so the executor keeps its `executor_id` and its
place in the pool, and no other executor's job changes. This is the same handover
`TestE2EMigration_CLToStandalone` performs. Propose it with `jd_propose_job` to the label step 7
put on the executor:

```sh
SPEC=$CLD/domains/ccv/staging_testnet/inputs/jobspecs/$EXE.toml
mkdir -p $(dirname $SPEC)
jq -j --arg n "$NODE" '.metadata.offchainConfigs.nopJobs[$n][$n + "-default-executor"].spec' \
  $CLD/domains/ccv/staging_testnet/datastore/env_metadata.json \
  | sed "s/^executorConfig = '''$/appConfig = '''/" > $SPEC
grep -c "^appConfig = '''$" $SPEC    # 1
grep -c executorConfig $SPEC         # 0
```

`jq -j` avoids adding a second trailing newline, so the only diff is the envelope rename. The
`jobspec_path` is relative to the repo root, where both local and CI runs execute. The job goes to
every enabled node in this product and environment that carries the label, which is only the
executor. A label that matches nothing proposes nothing and still reports success, so confirm the
executor actually started the job (below).

The processes approve their own job specs, so nothing needs accepting in the JD UI. Once both jobs
start:

```sh
kubectl --context $CTX -n $NS logs deploy/$VER | grep -i signer_address    # must print nothing
kubectl --context $CTX -n $NS port-forward deploy/$VER 8100:8100 & PF1=$!
kubectl --context $CTX -n $NS port-forward deploy/$EXE 8101:8101 & PF2=$!
kubectl --context $CTX -n $NS port-forward deploy/$VER 9988:9988 & PF3=$!
sleep 2
curl -s http://localhost:8100/health    # verifier: "status":"ready", or "degraded" naming what is not
curl -s http://localhost:8101/health    # executor: see below
curl -s http://localhost:9988/ready     # verifier bootstrap: now 200
kill $PF1 $PF2 $PF3
```

The executor job also lists `canton-devnet` and `solana-devnet` as destinations, and this process
has no config for non-EVM chains. So `ready`, or `degraded` naming only those two, is the expected
result; anything else degraded is a finding. On images built from #1521 on, the bootstrap server
also answers `/health/live` and `/health/ready` on 9988.

The generic `jd_propose_job` path delivers the job but does not canonicalize its saved metadata.
After the executor approves it, run `jd_reconcile_jobs` with the node ID returned by step 7 and the
exact standalone spec:

```yaml
  - jd_reconcile_jobs:
      payload:
        jobs:
          - nop_alias: $NODE
            jobspec_path: domains/ccv/staging_testnet/inputs/jobspecs/$EXE.toml
            node_id: <returned-executor-jd-node-id>
```

This changes only CLD metadata after reading JD jobs and proposals; it does not propose, revoke, or
delete a live job. Require one approved, byte-identical spec and confirm the saved executor job has
`mode = standalone`, its standalone node ID, and `appConfig`. Add reconciliation last in the
activation input when the returned IDs and environment node list are available to that run.
Otherwise use a separate read-only follow-up, as prod-testnet #21204 did; never rerun a completed
activation to add it. Do not regenerate NOP state until this is done.

### 10. Re-apply disabled chains, if step 1 recorded any

This can only happen now: the standalone `verifier_id` and the app-database rows exist only once
the job has started. The CLI reads the app DB from the mounted verifier secrets file, so exec in
the verifier container hits the right database. The flag is read at start, hence the restart.

```sh
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses list   # note verifier_id
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv quiesce pause           # quiesce
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses disable \
  --chain-selector <sel> --verifier-id <standalone-verifier-id>
kubectl --context $CTX -n $NS rollout restart deploy/$VER
kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv chain-statuses list   # disabled = true
```

Run the pause and the disable back to back. `quiesce pause` is a SIGSTOP, so the paused process
stops answering its liveness probe and the kubelet restarts the container after about a minute
(20s × 3). If that happens first, the disable lands on a running process and only the rollout
restart applies it. With `strategy: Recreate`, the restart stops the old pod before starting the
new one.

### 11. Prove it, then clean up

Prove both signing and the intended executor, not just committee execution. For signing, choose a
source in the verifier job's `on_ramp_addresses`: executor-pool membership does not imply that the
verifier serves the same source, so use separate messages when necessary. For executor targeting,
read `getExpectedNextMessageNumber(destChainSelector)`, build the canonical message with the
actual `executionGasLimit` from FeeQuoter's `quoteGasForExec` (which varies with payload length),
and compute `binary.BigEndian.Uint64(messageID[:8]) % len(executorPool)` with executor IDs sorted
lexicographically. Search payload suffixes until that index selects the target executor instead of
sending a probabilistic batch. Confirm the new signer appears at **both aggregators**, and confirm
the destination transaction came from that executor (`cast nonce <evmAddress> --rpc-url $RPC`
before and after). There is no onchain signer set to re-check: `apply-verifier-config` touches no
onchain state, and rule 4 covered the signer. Then:

```sh
# If the DON release was suspended, resume it (maintenanceMode keeps $CL at 0).
flux --context $CTX resume helmrelease chainlink-ccv -n $NS   # or patch spec.suspend=false directly
```

Commit the chainlink-deployments changes (topology.toml, the combined wave input, executor job
specs, nodes.json). The CL node's CCV job specs get removed the next time that node runs; while it
sits at zero replicas this is not blocking.

Before deleting key material, distinguish the temporary export from the durable signer in the
verifier bootstrap database. Keep `keyImport.expectedId`, the rendered `[key_import]` block, the
runtime Secret, the bootstrap database backups, and the keystore password. The public `expectedId`
is not sensitive and prevents a wrong or empty key from being accepted on a later boot.

Remove only the `verifier-keyimport` volume and its two mounts through GitOps. Roll out one verifier
first and verify all of the following before continuing with a batch:

- Its startup log says `key already exists, skipping import` and `Using signer address` with the
  recorded `$EXPECTED_ID`.
- Its public address endpoint returns that same address (never export the private key to check):

  ```sh
  kubectl --context $CTX -n $NS port-forward deploy/$VER 9988:9988 & PF=$!
  sleep 2
  curl -fsS -X POST http://localhost:9988/keystore/reader/getaddresses \
    -H 'Content-Type: application/json' \
    -d '{"KeyNames":["bootstrap_default_ecdsa_signing_key"]}'
  kill $PF
  ```

- Both aggregators accept a new signature from that signer. A healthy pod alone is insufficient.

After the canary passes, delete only the named local migration artifacts. Do not add the temporary
export or plaintext export password to routine backups; the standalone bootstrap database is the
new durable recovery copy.

```sh
rm -- /tmp/migration-$i/ocr2.json /tmp/migration-$i/export-password.txt \
  /tmp/migration-$i/verifier.key_import.toml
rmdir /tmp/migration-$i
rm -f -- /tmp/api-creds.txt /tmp/$EXE-bootstrap-secrets.toml \
  /tmp/$VER-bootstrap-secrets.toml /tmp/$VER-app-secrets.toml \
  /tmp/$CL-user-secret.toml
```

The final `rm` is idempotent cleanup for earlier runs; current runs already deleted the P6 TOMLs
immediately after their Secret creates. If `rmdir` reports remaining files, stop and inventory them
rather than recursively deleting the directory. Delete any password-manager entry created for the
export password, including one retained under the earlier backup instruction and its old versions.
Do not print secret contents or remove the standalone keystore password.

For each verified node, inspect only the key-import Secret's metadata, confirm no active workload or
ExternalSecret references it, then obtain approval and delete that exact Secret. Use `$CTX`, the
`TeamCCIPAdmin` context, for deletion; `$CTX_ENG` grants Secret creation, not deletion. If the admin
role is unavailable or the request is denied, stop and open a platform request instead:

```sh
kubectl --context $CTX -n $NS get secret $VER-keyimport-v1 -o json \
  | jq '{name: .metadata.name, labels: .metadata.labels, keys: (.data | keys)}'
kubectl --context $CTX -n $NS delete secret $VER-keyimport-v1
```

If it has `chain.link/deletion-protection-enabled=true`, obtain explicit approval before removing
that label. Do not delete the runtime secrets the instance files mount (`-v2` in staging, `-v1` in
prod-testnet); they are not migration exports. In particular, prod-testnet `$VER-secrets-v1` is
current, not an old generation, and contains the keystore password required to decrypt the stored
signer. Removing a mount does not delete the Secret, and deleting the Secret does not remove
external or backed-up copies.

Track any backup or snapshot known to contain the temporary export or password to deletion or
approved expiration with the infrastructure owner. Record outstanding retention dates; ordinary
deletion does not prove that no restorable copy remains.

The staging CL database was deleted with `skipFinalSnapshot: true` in
[chainlink-ccv-deploy#527](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/527) and is
not a rollback copy. After the temporary migration copies are disposed, the standalone bootstrap
database, its recovery backups, and its keystore password are the only signer recovery path. Do not
delete them.

### 12. Soak, then repeat for the next node

During the soak, check the transmitter balance on each of the five testnets by hand
(`cast balance <evmAddress> --rpc-url $RPC`); nothing alerts on it (P9). A balance that drops
faster than expected is a reason to look at transmit failures before the next node.

## Validation before calling it done

- Canary restart under traffic: `kubectl --context $CTX -n $NS delete pod <executor-pod>`
  mid-flight and watch TXM v2 recover. Nonce-gap detection waits 90 seconds for old transactions
  to confirm, then submits fee-bumped replacements; no message may end up stuck. This is the known
  residual risk, since TXM v2 keeps transactions in memory.
- Head-tracker cold start: a restarted process re-syncs from RPC instead of resuming persisted
  heads. That costs catch-up time, not correctness; measure it once and decide whether it is
  acceptable.
- Source-read mode: a cut-over node reads source logs over RPC, because the node-format EVM config
  cannot turn on the standalone LogPoller. If the CL nodes read through the node's LogPoller today
  (open question 4), that changes at the cutover; compare the cut-over node's source-reader
  progress and verification latency with its CL neighbors during the soak. Wherever a
  LogPoller-backed reader runs, put `verifier_source_reader_last_processed_finalized_block`
  against the chain head on a dashboard: a stalled LogPoller pins the reader's heads, so the gauge
  stops moving.
- Blind window: the standalone verifier has no checkpoint at first start, so it begins 500 blocks
  behind the finalized head (`verifier/pkg/sourcereader/service.go`). Messages finalized between
  step 5 and that block never get this node's signature; the rest of the committee covers them.
  500 blocks is about 100 minutes on Sepolia but about 17 on the 2s chains and about 2 on
  arbitrum-sepolia, so on the fast chains most of the window is uncovered by this node. Note the
  window length for the first node and confirm every message sent during it was verified.
- Dashboards: source-reader head gauges, critical-invariant counter, OffRamp read latency,
  transmit failures. Transmitter balances are checked by hand (P9, step 12).
- Admin console: once step 9's job runs,
  `kubectl --context $CTX -n $NS port-forward deploy/$VER 8105:8105` and open
  `http://localhost:8105` (the console refuses other host names). It should load and search this
  verifier's archive. The verifier logs `admin console listening` at start and
  `admin console stopped with error` if the console dies, which does not stop the job. Exercise
  the recovery flows from here, following the
  [remediation runbook](../runbooks/remediating-stuck-or-dropped-messages.md).
- Rollback path (exercise it on purpose at least once before the fleet is deep into the migration):
  1. Set `replicas: 0` in both standalone values files and deploy that change, so a later deploy
     cannot restart them. Wait for both standalone pods to terminate; no manual scale is needed.
  2. Repoint the JD record at the CSA key recorded in P8 (`jd_update_nodes` with the original
     `csa_key`) and remove `mode = "standalone"` from the node's topology block. With the CL topology
     and JD record restored, run `apply-verifier-config` (still with `consolidateAggregators: true`)
     and `apply-executor-config`, each scoped to `targetNops: ["$NODE"]`, then approve and verify the
     CL verifier and executor jobs before continuing.
  3. Take the node's index out of `maintenanceMode` and scale the CL node back up. Commit the values,
     topology, and pipeline inputs so the restored CL job delivery and zero standalone replicas persist.

## Open questions for the team

1. *(Resolved)* Node 0's `secondary` records are stale. Feeds Manager has no live secondary job,
   the namespace has no secondary-aggregator service, and the current metadata lists only node 0's
   default verifier and executor. There is no secondary migration or cleanup: no second standalone
   verifier and no onchain secondary-contract change. Node 0 joins the final wave with its live
   default jobs only.
2. *(Resolved)* Staging uses the internal faucet API for native-only shortfall top-ups to 2.5 per
   chain, then funds each executor 0.15 on all five chains. Failed or unsupported faucet requests
   need investigation or a faucet owner, not blind retries (P9).
3. *(Resolved)* Per-chain `txm_block_time` values for the five chains: Ethereum Sepolia (`11155111`)
   gets `12s` via `curatedTXMBlockTimeByChainID` (PR #1461), and Arbitrum Sepolia (`421614`),
   Base Sepolia (`84532`), Polygon Amoy (`80002`), and Avalanche Fuji (`43113`) use `2s` (the
   minimum `BlockTime` allowed by `chainlink-evm`). See P5.
4. Reader mode. The standalone LogPoller reader shipped in #1523. It is off by default and can
   only be turned on in the standalone-format EVM config (`[chains.<selector>]
   log_poller_source_reader_enabled = true`, plus an EVM secrets file with `[db].url`). Staging
   mounts the node-format TOML, so cut-over nodes read over RPC. The CL nodes set
   `[Feature] LogPoller = true` (`deploy/config/staging/chainlink-ccv/chains.yaml`), so if their
   image includes #1482 the CL-mode verifier already reads through the node's LogPoller, with the
   LogPoller's finality signal, and each cutover moves that node back to RPC reads and header-based
   finality checks. To see which reader a CL node runs, query its database:
   `select name from evm.log_poller_filters where name like 'ccv-verifier - %'`. Is RPC
   acceptable for staging, and should prod move to the standalone-format config?
5. *(Resolved in #1590)* `apply-executor-config` now routes to a standalone executor declared by
   `executor_node_name` or `ExecutorNodeID`, and fails closed without that reference or complete
   reconciled metadata. Staging's exact-spec `jd_propose_job` compatibility path remains documented
   in step 9, but it requires `jd_reconcile_jobs` afterward. The CLD dependency must include #1590;
   merely updating the input YAML on an older dependency does not add this routing.

## What staging does not decide

Prod batching must be derived from each affected chain's live membership and threshold;
prod-testnet does not have uniform 16-member committees, and the last migration wave includes
active nodes 16, 17, 18, and 20 while retiring idle node 19. External operator comms, public
image publishing (F2), operator-facing docs (F3), sweeping prod transmitter balances (F1),
and transmitter balance alerts (P9) get decided later, with staging results in hand.
