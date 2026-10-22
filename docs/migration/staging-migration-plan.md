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
    per-component details on `/health` and `/health/ready` (PR #1476).

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
VER=committee-verifier-evm-$i               # verifier: release = Deployment = JD node name
EXE=executor-evm-$i                         # executor: same three names
EXPECTED_ID=<from P8>                       # this node's OnchainSigningAddress from JD
```

Standalone names carry the chain family, following `committee-verifier-canton-0` in
chainlink-ccv-deploy and `committee-verifier-solana-0` / `executor-solana-0` in
chainlink-ccv-non-evm-deploy; other families will share this cluster and namespace. For each
standalone instance the griddle release name, the chart's `name` value (which becomes the
Deployment name), and the JD node name are the same string, so `$VER` and `$EXE` work in every
context below.

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
`apply-executor-config`, `jd_*`), unlike staging-migration, so no code change is needed:

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
throughout. The local file is gitignored; never commit it.

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
Second, node 0 is also the sole member of the `secondary` committee
(`[nop_topology.committees.secondary]` in `domains/ccv/staging_testnet/topology.toml`), so it
carries a secondary-committee verifier job this consolidation does not touch and its preflight
will show two jobs; see open question 1 and leave node 0 for last.

### P2. Images

No manual build. Every merge to main runs `build-push-main.yaml` in chainlink-ccv, which
publishes `containers/chainlink-ccv-verifier:<sha>-rc` and
`containers/chainlink-ccv-executor:<sha>-rc` (full 40-char commit SHA) to the primary and
secondary private ECRs. The staging aggregator and indexer values already pin images this way
(`deploy/config/staging/aggregator/common.yaml`:
`809128755817.dkr.ecr.us-west-2.amazonaws.com/containers/chainlink-ccv-aggregator:<sha>-rc`).
So: take a recent main SHA that includes the migration tooling and pin
`image.tag: <sha>-rc` in the P3 values.

A release tag is the alternative. release-please cuts the root `vX.Y.Z` tag
(`.release-please-manifest.json` is at 0.4.0, so the next is v0.5.0) and `release-publish.yaml`
publishes the same images tagged `vX.Y.Z`, no `-rc`. Either works for staging; the SHA image
exists minutes after the merge, the release image when we choose to cut one. `manual-build.yaml`
(tag `manual-<ref>-rc`, primary ECR only) is for testing an unmerged ref and is not part of this
plan.

### P3. Charts and config dirs

Verifier: the `committee-verifier-base` chart exists in chainlink-ccv-deploy
(`deploy/charts/committee-verifier-base`, v0.1.3, listed in `build.charts.inventory`, with
`templates/role-otel-sidecar.yaml` for the OTEL sidecar's `k8sattributes` processor and
`generic-app.selectorLabels` on `pdb.yaml`/`servicemonitor.yaml`); the verifier releases point
straight at it.

Executor: `deploy/charts/executor-evm` (v0.1.1, listed in `build.charts.inventory`) is modeled on
`chainlink-ccv-non-evm-deploy/deploy/charts/executor-solana` and `committee-verifier-base`: image,
`configs` rendered into one ConfigMap, `volumes`/`volumeMounts` for the secret and config files,
`envVars`, `/health` probes on `service.port`, optional `managedDB`, and the OTEL sidecar RBAC role.
The existing `push-helm-charts.yaml` workflow publishes both charts on merge.

Both processes take their file locations from the same env vars (`BOOTSTRAPPER_CONFIG_PATH`,
`EVM_CONFIG_PATH`, `BOOTSTRAPPER_SECRETS_PATH`, `COMMITTEE_VERIFIER_SECRETS_PATH`;
`bootstrap/bootstrap.go`, `integration/pkg/accessors/evmconfig/config.go`,
`verifier/pkg/vsecrets/vsecrets.go` in chainlink-ccv). The bootstrap health endpoint is `/health`
on `[server].listen_port`, default 9988 (`docs/config/bootstrap/config.documented.toml`). Note that
in JD mode (`startWithJDLifecycle`), the app HTTP server (`:8100` on verifier, `:8101` on executor)
only starts after JD proposes a job in cutover step 9, while the bootstrap `infoServer` on `:9988`
starts immediately at boot (`/health` returns 200; `/ready` returns 503 until a job starts). Both
`livenessProbe` and `readinessProbe` in Helm values therefore target `/health` on port `9988` so
pods deployed in P7/step 6 pass readiness before step 9.

Config dirs, one per family chart, named like the releases (scaffolded for node 1):

- `deploy/config/staging/committee-verifier-evm/`: `common.yaml` (image, resources, labels,
  sidecar), `config.yaml` (non-secret `configs:` TOMLs), `committee-verifier-evm-$i.yaml`
  (`name`, `replicas`, the secret volumes).
- `deploy/config/staging/executor-evm/`: the same three.

### P4. Databases (3 per node, on their own cluster)

Verifier-bootstrap, verifier-app, executor-bootstrap. They cannot share a database (both migration
runners use goose's default version table). 63 databases if the whole committee migrates;
provision at least the next node's three before its window.

Put them on a new Aurora cluster rather than on `chainlink-ccv-dons`, which hosts the 21 CL node
databases. The reason is isolation in both directions: the standalone processes cannot load the
DON cluster, and if a standalone database has to be dropped, or the whole cluster wiped after a
bad cutover, nothing CL-mode is on it, so the rollback path (scale the CL node back up, repoint
its CSA key) never depends on the new cluster. Both live in
`$DEPLOY/deploy/config/staging/database-provisioner/database-provisioner.yaml`. The cluster,
modeled on the `chainlink-ccv-dons` block minus its restore snapshot:

```yaml
databaseClusters:
  chainlink-ccv-evm-standalone:
    engine: aurora-postgresql
    engineVersion: "17.5"
    deletionProtection: true
    backupRetentionDays: 7
    instances:
      count: 1
      instanceClass: db.t4g.medium
```

Instance class and storage type are sizing calls; `db.t4g.medium` is what the two canton
verifier clusters in the same file use. Revisit after the first soak. Add the cluster in the same
PR as node 1's databases and confirm it is ready before expecting connection secrets.

Database map keys must stay at or under 43 chars (the composition appends `-provider-sql-config`
and the result is a 63-char k8s label). Set `connectionSecret.name` explicitly. Node 1's block, as
the model:

```yaml
databases:
  ccv-evm-1-verifier-bootstrap:
    databaseClusterName: chainlink-ccv-evm-standalone
    databaseName: ccv_evm_1_verifier_bootstrap
    connectionSecret:
      name: ccv-evm-1-verifier-bootstrap-database-connection
  ccv-evm-1-verifier-app:
    databaseClusterName: chainlink-ccv-evm-standalone
    databaseName: ccv_evm_1_verifier_app
    connectionSecret:
      name: ccv-evm-1-verifier-app-database-connection
  ccv-evm-1-executor-bootstrap:
    databaseClusterName: chainlink-ccv-evm-standalone
    databaseName: ccv_evm_1_executor_bootstrap
    connectionSecret:
      name: ccv-evm-1-executor-bootstrap-database-connection
```

Deploy (PR + `.deploy stage`), then verify:

```sh
kubectl --context $CTX -n $NS get databasecluster chainlink-ccv-evm-standalone
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
| `avalanche-testnet-fuji` | `14767482510784806043` | `43113` | `10` | `true` | `2s` | `generic_fallback` | 2 (all WS) |

No manual `Transactions.TransactionManagerV2.BlockTime` overrides are needed in the staging
`evm-config.toml`: Ethereum Sepolia receives `12s` from `curatedTXMBlockTimeByChainID` (PR #1461),
and upstream `chainlink-evm` rejects `BlockTime < 2s` (`DefaultTXMBlockTime = 2 * time.Second`),
so `2s` is already the minimum legal value for Arbitrum Sepolia, Base Sepolia, Polygon Amoy, and
Avalanche Fuji. Verified again in cutover step 2 with `inspect-config`.

### P6. Secrets per node

Three TOMLs per node: verifier bootstrap secrets (bootstrap DB `[db].url` plus
`[keystore].password`), verifier app secrets (app DB `[db].url` plus `[[aggregators]]` HMACs,
reusing the creds the CL jobs use today, keyed by the P1 `secret_name`s), executor bootstrap
secrets. Schemas: `docs/config/bootstrap/secrets.documented.toml` and
`docs/config/verifier/secrets.documented.toml` in chainlink-ccv. Compose the DB URLs from the P4
connection secrets:

```sh
db_url() { kubectl --context $CTX -n $NS get secret "$1" -o go-template='postgres://{{index .data "POSTGRES_USER" | base64decode}}:{{index .data "POSTGRES_PASSWORD" | base64decode}}@{{index .data "POSTGRES_HOST" | base64decode}}:{{index .data "POSTGRES_PORT" | base64decode}}/{{index .data "POSTGRES_DB" | base64decode}}'; }
db_url ccv-evm-$i-verifier-bootstrap-database-connection
```

Create versioned secrets named after the instance (create-not-patch RBAC; a change later means
`-v2` plus a values repoint, per the canton README workflow):

```sh
kubectl --context $CTX_ENG -n $NS create secret generic $VER-secrets-v1 \
  --from-file=bootstrap-secrets.toml=/tmp/$VER-bootstrap-secrets.toml \
  --from-file=verifier-secrets.toml=/tmp/$VER-app-secrets.toml
kubectl --context $CTX_ENG -n $NS create secret generic $EXE-secrets-v1 \
  --from-file=bootstrap-secrets.toml=/tmp/$EXE-bootstrap-secrets.toml
```

### P7. Griddle releases, verifiers at zero replicas

Two entries per node in `$DEPLOY/griddle.yaml` under the stage env, next to the canton entries;
add them per migration batch rather than all 42 upfront. `ccip_env: stage` is required (the
image-sync-check workflow errors without it). Shape:

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
      path: deploy/charts/executor-evm
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

The executors may run immediately (`replicas: 1`); they just generate their transmitter key and
idle. The verifiers must not: rule 3 means a verifier's first boot has to happen inside its node's
cutover window, after its key-import secret exists. Set `replicas: 0` in each verifier's values.
That keeps the Deployment object present so a later scale works, and Flux drift detection is
configured to ignore `/spec/replicas`, so a manual scale is not fought by the reconciler (it is
only overwritten by the next actual deploy of that release). Preview before deploying:

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

Record each node's `OnchainSigningAddress`; that value is `$EXPECTED_ID` in step 3. While here,
also record each node's current CSA key: the rollback path needs it (step 7).

Pre-extracted from `domains/ccv/staging_testnet/state_v2.json` and `topology.toml` (all 21 nodes are in `executor_pools.default` on all 5 EVM chains; the `default` committee memberships per node are listed in the last column):

| `i` | `NODE` (`chainlink-ccv-staging-$i`) | JD `nodeID` | `EXPECTED_ID` (`OnchainSigningAddress`) | Current `csaKey` (for rollback) | `default` Committee Chains |
|---|---|---|---|---|---|
| `0` | `chainlink-ccv-staging-0` | `node_tSJyxmzinkkBCTBmmWEif` | `0xf5a79545c47626e887c997947bc151dd8e1cd119` | `be7b515dcba8644713ef97b2d13d14a8bb9bd82dae57166db29c406e4e2baa51` | sepolia, base-sepolia, fuji (+ `secondary` on all 5) |
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

Identify what funds staging node accounts today and who sends from it (open question 2).

Balance alerts are out of scope for staging. The CL nodes have none today that this plan could
carry over: `[EVM.BalanceMonitor] Enabled = true` in
`deploy/config/staging/chainlink-ccv/chains.yaml` only exports the balance metric, and nothing in
chainlink-ccv-deploy defines an alert on it. The standalone executor does not run the balance
monitor at all, so an unfunded transmitter surfaces as failed broadcasts. The soak in step 12
therefore includes a manual balance check on the five testnets. Alerts are a prod item.

## The cutover, per node (one at a time)

### 1. Preflight

```sh
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink admin login --file /v2Secret/.api
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink jobs list
kubectl --context $CTX -n $NS exec deploy/$CL -- chainlink node ccv chain-statuses list
```

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

Pull the node's effective EVM TOML (render the release locally with
`gcli helm template -e stage -N chainlink-ccv -c griddle.yaml`, or read the live ConfigMap, or
inspect the standalone `evm-config.toml` from `deploy/config/staging/committee-verifier-evm/config.yaml`), then:

```sh
cd $CCV
go run ./cmd/verifier/committee ccv migrate inspect-config --config /tmp/node-$i.toml
```

Confirm `failed_chains` is empty and each of the five chains matches the P5 baseline (`12s` via
`curated_chain_default` on Ethereum Sepolia; `2s` floor via `generic_fallback` on Arbitrum Sepolia,
Base Sepolia, Polygon Amoy, and Avalanche Fuji).

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
kubectl --context $CTX_ENG -n $NS create secret generic $VER-keyimport-v1 \
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
expected here. The images are distroless (no shell, no wget), so probe over a
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

Repoint the node's existing JD record at the verifier's CSA key (this keeps the node ID and
alias), and register the executor as a new JD node named after its release. Record the old CSA
key first; rollback is repointing the record back at it.

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json     # node id + current csa key
go run ./domains/ccv/cmd jd node update -e staging_testnet -i <node_id> -k csa_key -v <verifier_csa_hex>
go run ./domains/ccv/cmd jd node register -e staging_testnet \
  -n $EXE -a <executor_csa_hex> \
  -l product=ccv -l environment=staging_testnet
go run ./domains/ccv/cmd jd node list -e staging_testnet -f json     # wait: both connected
```

Wait until JD reports both connected before step 9: a job proposed to a record whose owner has not
dialed in sits unclaimed. Two cautions: check `jd node update --help` for the `-k` spelling
(`csa_key` vs `csa-key` differs between framework versions), and `jd node register` appends the
new node id to `domains/ccv/staging_testnet/nodes.json`, which is part of the commit.

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
  cast send <evmAddress> --value 0.5ether --rpc-url $RPC --private-key $FUNDER_KEY
done
```

Record the address in the cutover notes; the balance check in step 12 uses it. The old per-chain
transmitter balances stay put: they are testnet tokens and the rollback path, so nothing gets
swept in staging.

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
kubectl --context $CTX -n $NS port-forward deploy/$VER 8100:8100 & PF1=$!
kubectl --context $CTX -n $NS port-forward deploy/$EXE 8101:8101 & PF2=$!
kubectl --context $CTX -n $NS port-forward deploy/$VER 9988:9988 & PF3=$!
sleep 2
curl -s http://localhost:8100/health         # expect "status":"pass" (not "degraded"; /health/ready and /health/live also available)
curl -s http://localhost:8101/health         # expect "status":"pass" (not "degraded")
curl -s http://localhost:9988/ready          # now 200
kill $PF1 $PF2 $PF3
```

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
- Dashboards: source-reader head gauges, critical-invariant counter, OffRamp read latency,
  transmit failures. Transmitter balances are checked by hand (P9, step 12).
- Rollback path: scale the CL node back up and repoint its JD record at the CSA key recorded in
  step 7 (`jd node update -i <node_id> -k csa_key -v <original_csa_hex>`). Exercise it on purpose
  at least once before the fleet is deep into the migration.

## Open questions for the team

1. Node 0 is the sole member of the `secondary` committee
   (`[nop_topology.committees.secondary]` in `domains/ccv/staging_testnet/topology.toml`:
   threshold 1 on all five chains, with two aggregators of its own at
   `chainlink-ccv-secondary-aggregator-1/2.ccip.stage.internal.griddle.sh`). It is real on both
   sides: the staging datastore holds a `secondary`-qualified `CommitteeVerifier` and
   `CommitteeVerifierResolver` per chain, and node 0's job
   `chainlink-ccv-staging-0-secondary-aggregator-secondary-verifier` is in `state_v2.json`. No
   release in chainlink-ccv-deploy's `griddle.yaml` serves those two aggregator hostnames,
   though. So after P1 node 0 still runs two verifier jobs and fails the one-job preflight. Do we
   retire the secondary committee (revoke the job, leave the contracts), or give node 0 a second
   standalone verifier for it? Either way node 0 migrates last.
2. What is the staging funding source for node accounts, and who owns sending from it? (P9)
3. *(Resolved)* Per-chain `txm_block_time` values for the five chains: Ethereum Sepolia (`11155111`)
   gets `12s` via `curatedTXMBlockTimeByChainID` (PR #1461), and Arbitrum Sepolia (`421614`),
   Base Sepolia (`84532`), Polygon Amoy (`80002`), and Avalanche Fuji (`43113`) use `2s` (the
   minimum `BlockTime` allowed by `chainlink-evm`). See P5.

## What staging does not decide

Prod batching (16 members, threshold 9, so at most 7 nodes mid-cutover at once), external
operator comms, public image publishing (F2), operator-facing docs (F3), sweeping prod
transmitter balances (F1), and transmitter balance alerts (P9). Those get decided later, with
staging results in hand.
