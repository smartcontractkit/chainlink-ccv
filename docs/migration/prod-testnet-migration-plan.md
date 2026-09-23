# Prod-testnet migration: CL mode to standalone CCV

Audience: CCV team. Scope: the `prod_testnet` environment, meaning the 21-node
`chainlink-ccv-testnet` DON in the prod cluster (namespace `chainlink-ccv-testnet`, JD
aliases `ccv-prod-testnet-0..20`). The `default` committee serves 60 chain configs: 59
EVM chains, each listing the same 16 members (`ccv-prod-testnet-0..15`) with threshold 9,
plus one Canton chain served by the four `chainlink-canton-committee-verifier-N` nodes,
which already run `mode = "standalone"`. The two aggregators are the public pair,
`aggregator-1.testnet.ccip.chain.link` and `aggregator-2.testnet.ccip.chain.link`.

This is the third and final CLL-controlled environment, and the dress rehearsal for
prod-mainnet. Staging proves the cutover mechanics; prod-testnet proves them under
production load at ~60-chain scale; prod-mainnet proves the external-operator path.
Nothing in this document unblocks an external operator — that is a separate program, and
it starts only after the go/no-go at the bottom of this one.

Reference procedure: `chainlink-ccv/docs/migration/evm-cl-to-standalone.md` (written for
external operators) and `chainlink-ccv/docs/migration/staging-migration-plan.md` (the
staging execution plan). The per-node mechanics are identical to staging; this document
lists the deltas rather than repeating the procedure. Where a step says "as in staging,"
execute the staging plan's step with the substitutions in "Conventions".

## What prod-testnet adds over staging

1. **Real traffic, real users.** This environment serves integrators on public testnets.
   Cutovers need a posted schedule, a quiet window per node, and a real lane for the
   confirmation message in step 11. Staging's "pick a quiet moment" becomes "announce it,
   then pick a quiet moment."
2. **60 EVM chains, not 5.** The pre-cutover config diff runs per chain. The curated
   per-chain TXM block-time table covers known slow chains; every chain
   reporting `generic_fallback` in the diff gets an explicit value or a recorded
   acceptance. This is the scale test for the config tooling.
3. **Balance alerting is mandatory.** Staging skipped it with manual soak checks. Here
   the external alert on each new executor transmitter address, per chain, goes up before
   that node's jobs start. This is the rehearsal for the prod-mainnet alerting
   requirement.
4. **Small parallel batches become possible.** Each node serves all 59 EVM chains, so one
   node down leaves every chain at 15 of 9 — a wide margin, and CLL controls every node,
   so there is no external scheduling to respect. Stay one-at-a-time for the first three
   nodes; after that, batches of two or three are reasonable if the soaks are clean.
   Derive the number per batch from the live committee config, not from this paragraph.
5. **Release images, not `-rc` SHAs.** The standalone pair deployed here should run the
   same release-tagged image (`vX.Y.Z`) that prod-mainnet operators will be given. This
   is the end-to-end validation of the image-publishing path before it becomes external.
6. **No secondary committee.** Staging's node-0 complication does not exist here. But see
   open question 1: only 16 of the 21 nodes have an EVM committee role.

## Hard rules (unchanged from staging)

1. One node at a time for the first three nodes; small batches only after clean soaks.
2. Export while the node is up; stop the node before the standalone verifier starts. One
   JD record cannot have two owners.
3. Never boot the verifier without its `[key_import]` block.
4. `ApplyVerifierConfig` must produce no contract transaction. A proposed signer change
   means the imported key is wrong. Stop.
5. After the standalone verifier job first starts, re-apply and confirm the disabled flag
   for any chain that was disabled on the node before the cutover.

## Conventions

Every command below assumes this block has been pasted into the shell. AWS SSO expires
every 8h.

```sh
aws sso login --sso-session griddle-session

# kubeconfig context names as in chainlink-ccv-deploy AGENTS.md; adjust to your kubeconfig
export CTX=platform-ccip-prod                          # cluster reads, exec, scale
export CTX_ENG=platform-ccip-prod-engineer             # secret creation (RBAC: create, not patch)
export NS=chainlink-ccv-testnet

CCV=~/dev/dev/chainlink-ccv
CLD=~/dev/dev/chainlink-deployments
DEPLOY=~/dev/dev/chainlink-ccv-deploy

# per cutover; i = 0..15 (nodes 16..20: see open question 1)
i=1
NODE=ccv-prod-testnet-$i                    # JD alias, topology alias
CL=chainlink-ccv-testnet-$i                 # the node's k8s deployment, service, secret prefix
VER=committee-verifier-evm-$i               # verifier: release = Deployment = JD node name
EXE=executor-evm-$i                         # executor: same three names
EXPECTED_ID=<from P8>                       # this node's OnchainSigningAddress from JD
```

Deploys are IssueOps, as in staging: branch in chainlink-ccv-deploy, PR (ready, not
draft), comment `.deploy prod` on it, thumbs-up the confirmation comment. There is no
auto-deploy on merge. Note the `prod` section of `griddle.yaml` mixes prod-testnet and
prod-mainnet releases (namespace separates them); the env split is tracked by a TODO in
that file — be careful that a `.deploy prod` comment deploys every instance in the env,
so coordinate with whoever owns concurrent prod-mainnet work.

Pipelines: `prod_testnet` registers the shared CCV pipelines
(`apply-verifier-config`, `apply-executor-config`, `jd_*`) via
`RegisterSharedPipelinesWithoutEVMOwnershipPreHook` — the env-wide EVM-ownership
pre-hook is skipped because lane ownership is partial (Lombard) on Fuji, Base, and BSC.
Scope every cutover input with `targetNops` as in staging; do not run env-wide inputs
here. The canonical path (commit input + `/run-pipelines`) works unchanged.

## Prerequisites (before the first node migrates)

### P0. Access, pipelines, and JD auth

As in staging P0, against the prod contexts:

- `kubectl --context $CTX_ENG -n $NS auth can-i create secrets` must print yes for everyone
  driving a cutover. If not, Okta access request (team `ccip`, prod roles).
- Local JD/pipeline runs need the `prod_testnet` credentials in
  `domains/ccv/.config/local/config.prod_testnet.yaml`, which does not exist today —
  same scaffold command and same `#cld-guardian-support` ask as staging, or use
  `/run-pipelines` throughout. Decide before P8.

### P1. Consolidate verifier jobs (run while still in CL mode)

Two aggregators means each node runs two `ccvcommitteeverifier` jobs today — the
prod-testnet jobs use two verifier IDs per database (`aggregator-1-default-verifier`,
`aggregator-2-default-verifier`). Standalone runs one job; legacy `verifier_id`s become
`secret_name`s. Same changeset input as staging P1, environment `prod_testnet`, dry-run
first. There is no secondary-committee exception here, but scope the change to the 16
EVM-serving nodes (open question 1).

### P2. Images

Run the release-tagged image (`vX.Y.Z` from `release-publish.yaml`), not a `-rc` SHA.
The tag must include the curated per-chain TXM block-time table — it is load-bearing at
this chain count. Confirm the tag matches what the prod-mainnet operator image will be.

### P3. Charts and config dirs

Charts exist once staging lands them (`committee-verifier-base` and the `executor-evm`
chart copied from the Solana executor chart). Create the prod-testnet value trees:

- `deploy/config/prod-testnet/committee-verifier-evm/`: common, config, per-instance values.
- `deploy/config/prod-testnet/executor-evm/`: the same three.

Model them on the staging trees; the only intended differences are environment labels,
the image tag (P2), and resource sizing if staging's soak showed a need. Probe
configuration is the same (liveness → app `/health` on 8100/8101, readiness → bootstrap
`/ready` on 9988).

### P4. Databases (3 per migrating node, on their own cluster)

Verifier-bootstrap, verifier-app, executor-bootstrap per node; they cannot share (goose
version table). 48 databases if nodes 0..15 migrate; 63 if 16..20 join (open question 1).
Add a new cluster `chainlink-ccv-testnet-evm-standalone` to
`deploy/config/prod-testnet/database-provisioner/database-provisioner.yaml`, modeled on
the staging cluster — a new cluster, not `chainlink-ccv-testnet-dons`, for the same
two-way isolation: the rollback path never depends on it. Sizing: the DON cluster runs
2× `db.r8g.xlarge` on aurora-iopt1; the Canton standalone clusters run a single
`db.t4g.medium`. Start at the Canton shape, revisit after the first soak with real
traffic. Map keys ≤ 43 chars; set `connectionSecret.name` explicitly.

### P5. Per-chain config review at 60-chain scale

For each of the 59 EVM chains: run `ccv migrate inspect-config` against the node EVM
TOML (the `chainlink-ccv-testnet` values carry 61 `[[EVM]]` entries; the committee
serves 59 — reconcile the difference during the first node's diff) and record
accept-or-correct for every warning, every `failed_chains` entry, and every chain whose
`txm_block_time_source` is `generic_fallback`. This is one recorded review, reused
across nodes, re-run when the config changes.

### P6. Secrets per node

As in staging P6: three TOMLs per node (verifier bootstrap, verifier app with the
aggregator HMACs under the P1 `secret_name`s, executor bootstrap), DB URLs composed from
the P4 connection secrets, created via `$CTX_ENG` with `-v1` naming.

### P7. Griddle releases, verifiers at zero replicas

As in staging P7, in the `prod` section of `griddle.yaml` with `ccip_env: prod-testnet`:
`committee-verifier-evm-$i` and `executor-evm-$i` per migrating node, verifiers at
`replicas: 0` until each one's key-import secret exists (hard rule 3). Add per batch, not
all upfront.

### P8. expected_id per node, from JD

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e prod_testnet -f json
go run ./domains/ccv/cmd validate nop-support -e prod_testnet
```

Record each node's `OnchainSigningAddress` (`$EXPECTED_ID` in step 3) and current CSA
key (rollback). Note `nodes.json` holds 25 records: the 21 CL DON nodes plus the four
Canton standalone verifiers — do not touch the Canton records.

### P9. Funding source and balance alerts

Identify what funds the per-chain transmitter accounts today across ~60 public testnets
and who sends from it. Unlike staging, balance alerts are in scope: each new executor
transmitter address gets an external balance alert per chain before its jobs start.
Wherever the alert lives, it must page someone who can fund.

## The cutover, per node

Execute the staging plan's per-node procedure (steps 1–12) with these substitutions and
additions:

| Staging reference | Prod-testnet form |
|---|---|
| `staging_testnet` env / `platform-ccip-stage*` contexts | `prod_testnet` / `platform-ccip-prod*` |
| `chainlink-ccv-staging-$i` / `chainlink-ccv-$i` | `ccv-prod-testnet-$i` / `chainlink-ccv-testnet-$i` |
| `flux suspend helmrelease chainlink-ccv` | `flux suspend helmrelease chainlink-ccv-testnet` |
| `maintenanceMode.specificNodes` in staging `overrides.yaml` | same mechanism in `deploy/config/prod-testnet/chainlink-ccv-testnet/overrides.yaml` (chart supports it; this env introduces it, as staging does) |
| five testnets for funding and balance checks | the node's ~60 chains (script the balance check; manual does not scale) |
| step 11 confirmation message on a staging lane | a real lane this node verifies; announce the window first |
| soak: manual balance check | soak: balance alerts live, TXM v2 metrics on dashboards, transmit-failure review |

After the first three nodes, batches of two or three are acceptable with clean soaks;
derive the batch size from the live committee config. Nodes 16..20 are out of scope until
open question 1 is answered.

## Validation before calling it done

Every item from staging's validation, here under real traffic:

- **Canary restart under traffic (mandatory):** delete an executor pod mid-flight on a
  busy chain and watch TXM v2 recover — 90s nonce-gap wait, fee-bumped replacements, no
  stuck message. This is the production gate from the TXM v2 assessment; staging's run
  was rehearsal, this one counts.
- **Head-tracker cold start** on a busy chain: measure the re-sync cost under real head
  velocity; decide acceptability.
- **Rollback drill:** repeat once here even though staging drilled it — the prod contexts
  and release names differ, and the people on the prod-mainnet rotation should run it.
- **Dashboards and alerts:** source-reader head gauges, critical-invariant counter,
  OffRamp read latency, transmit failures, and the TXM v2 metric names
  (`txm_num_broadcasted_transactions`, `txm_num_confirmed_transactions`,
  `txm_num_nonce_gaps`, `txm_time_until_tx_confirmed`); confirm every transmitter-balance
  alert fires on a test drain.
- **Full-fleet soak:** two weeks, all 16 nodes standalone, before the go/no-go.

## Go/no-go to prod-mainnet

Operator comms for prod-mainnet may start when all of these hold:

- [ ] All 16 EVM-serving nodes cut over and confirmed (message per lane, signer sets
      unchanged on chain).
- [ ] Two-week full-fleet soak with no sev and no unexplained transmit failure.
- [ ] Canary restart, rollback drill, and alert verification results written down.
- [ ] The per-chain config review (P5) archived; every deviation has an owner.
- [ ] Runbook corrections from this environment fed back into
      `evm-cl-to-standalone.md` — prod-mainnet operators get the corrected doc.

## Open questions

1. **Nodes 16..20.** Committee chain configs list only `ccv-prod-testnet-0..15`; nodes
   16–20 have no EVM verifier or executor role in the committee, yet the DON runs 21
   nodes. What are they (expansion, standby, decommission candidates)? They do not
   migrate until this is answered; P4's database count depends on it (48 vs 63).
2. **`storage_locations` lists `aggregator-1.testnet.ccip.chain.link` twice** in
   `prod_testnet/topology.toml` — probable typo for aggregator-2. Harmless for the
   cutover (the changesets read the `aggregators` block, which is correct), but fix it
   before prod-mainnet config generation treats it as truth.
3. Funding source per chain (P9) — inventory the ~60 testnet funders before the first
   node.
4. The 61 vs 59 `[[EVM]]` entries vs committee chains (P5) — name the two chains the
   nodes serve that the committee does not, or the reverse.

## What prod-testnet does not decide

External operator scheduling and comms, the HSM/KMS path for operators whose keys cannot
be exported, the NOP funding model (each prod-mainnet operator funds their own executor),
prod-mainnet batching under external windows, and public image publishing approvals
(F2/F3 in the epic). Those belong to the prod-mainnet program, which the go/no-go above
gates.
