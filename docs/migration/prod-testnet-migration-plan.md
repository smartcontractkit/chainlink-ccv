# Prod-testnet migration: CL mode to standalone CCV

Audience: CCV team. Scope: the `prod_testnet` environment, meaning the 21-node
`chainlink-ccv-testnet` DON in the prod cluster (namespace `chainlink-ccv-testnet`, JD
aliases `ccv-prod-testnet-0..20`). The `default` committee serves 63 chain configs: 61
EVM chains with chain-specific membership and thresholds. Forty-nine EVM chain configs include
at least one of nodes 16, 17, 18, and 20; node 19 has no committee or executor role. Canton
and Solana chains have standalone components already separate. The two
aggregators are the public pair, `aggregator-1.testnet.ccip.chain.link` and
`aggregator-2.testnet.ccip.chain.link`.

This is the third and final CLL-controlled environment, and the dress rehearsal for
prod-mainnet. Staging proves the cutover mechanics; prod-testnet proves them under
production load at ~61-chain scale; prod-mainnet proves the external-operator path.
Nothing in this document unblocks an external operator — that is a separate program, and
it starts only after the go/no-go at the bottom of this one.

Technical reference: [EVM standalone verifier and executor](../verifier/evm-standalone.md).
The per-node mechanics are identical to the [staging execution plan](staging-migration-plan.md);
this document lists the deltas rather than repeating the procedure. Where a step says "as in
staging," execute the staging plan's step with the substitutions in "Conventions".

## Execution status

- **Staging is complete:** all 21 EVM nodes are standalone.
- **Prod-testnet migration and activation are complete for all 20 active EVM nodes.** Nodes 1–5
  deployed in [chainlink-ccv-deploy #531](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/531)
  and activated in [chainlink-deployments #21167](https://github.com/smartcontractkit/chainlink-deployments/pull/21167).
  Nodes 6–10 deployed in [chainlink-ccv-deploy #532](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/532)
  and activated in [chainlink-deployments #21168](https://github.com/smartcontractkit/chainlink-deployments/pull/21168).
  Nodes 11–15 deployed in [chainlink-ccv-deploy #533](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/533)
  and activated in [chainlink-deployments #21169](https://github.com/smartcontractkit/chainlink-deployments/pull/21169).
  Every targeted message reached both aggregators and executed from the intended transmitter.
  Pre-cutover disabled flags were restored on every affected verifier.
- **The active-four wave is complete and verified.** Nodes 16, 17, 18, and 20 deployed in
  [chainlink-ccv-deploy #545](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/545)
  and activated in [chainlink-deployments #21317](https://github.com/smartcontractkit/chainlink-deployments/pull/21317);
  the [activation run](https://github.com/smartcontractkit/chainlink-deployments/actions/runs/42929384018)
  succeeded. Both aggregators authenticated every preserved signer, and the intended-transmitter
  Sonic executions succeeded for nodes [16](https://ccip.chain.link/msg/0x1623d2d43fcf7ea7a4a416b8d619ebc41c53ee7b45a6c5503fb6b1cc61306805),
  [17](https://ccip.chain.link/msg/0xf563c5721ee83138d5a92913419eeb861dd26087d127567042aa87cfe1908a4b),
  [18](https://ccip.chain.link/msg/0x7b77f75521df2a09c72cde60b71ca41b240534e58bf4a2a760ba3d0ecae8046c),
  and [20](https://ccip.chain.link/msg/0x04192a059ff55a2a4b4495312615e69d11a68b1e0ba52f87ab525c1f74c7a327).
  Their recorded disabled flags were restored. Idle node 19 had no JD identity, jobs, signer
  inventory, or committee/executor membership and was retired without a standalone replacement.
- **Executor metadata and state reconciliation are complete.** In addition to the earlier
  reconciliation in #21204, #21230, and #21256,
  [chainlink-deployments #21320](https://github.com/smartcontractkit/chainlink-deployments/pull/21320)
  reconciled the active four; its [pipeline run](https://github.com/smartcontractkit/chainlink-deployments/actions/runs/42935993341)
  succeeded. The scoped [state-generation run](https://github.com/smartcontractkit/chainlink-deployments/actions/runs/42938300136)
  includes all 20 standalone executor NOPs with the correct CSAs, transmitters, and connectivity;
  none is misplaced in `v2Nops`.
- **Legacy decommissioning is complete.** [chainlink-ccv-deploy #543](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/543)
  removed the legacy release, its Aurora cluster, and all 21 legacy logical database claims. After
  reference checks and explicit approval, 87 remaining legacy Secrets were also deleted. All 20
  standalone verifier/executor pairs, 20 database clusters, and 60 logical databases remained
  healthy, and neither aggregator developed authentication errors. This was not a complete legacy
  balance recovery: the accepted exceptions included 12 unconfirmed withdrawals (11 Shibarium and
  one Metis) and the residual-balance/RPC exceptions recorded during the final audit.
- **Temporary migration-export mounts and key-import Secrets were removed on 2026-11-13.** [chainlink-ccv-deploy #551](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/551)
  proved the canary and [#552](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/552)
  completed the remaining rollout. All 20 active verifiers retained their expected public signers
  and had accepted writes to both aggregators. After explicit approval and metadata/reference checks,
  all 20 unmounted key-import Secrets were deleted. The runtime `-v1` Secrets were unchanged and all
  20 verifier Deployments remained healthy. The only remaining disposal work is any operator-held
  export-password entries or backup copies, whose inventory cannot be established from cluster state.
  Do not claim unrecoverable disposal until every temporary copy is deleted or expires under the
  approved retention process.
- The full-fleet two-week soak began on 2026-11-11; its earliest completion date is 2026-11-25.
  The restart/rollback drills, monitoring ownership handoff, and prod-mainnet release/config
  decisions remain open. Migration and decommissioning do not constitute prod-mainnet go/no-go.

## What prod-testnet adds over staging

1. **Real traffic, real users.** This environment serves integrators on public testnets.
   Cutovers need a posted schedule, a quiet window per node, and a real lane for the
   confirmation message in step 11. Staging's "pick a quiet moment" becomes "announce it,
   then pick a quiet moment."
2. **61 EVM chains, not 5.** The pre-cutover config diff runs per chain. While
   `curatedTXMBlockTimeByChainID` (PR #1461) covers common >2s chains (`txm_block_time_source:
   "curated_chain_default"`), every chain that still falls back to `txm_block_time_source:
   "generic_fallback"` (`2s`) in the diff gets an explicit `BlockTime` value in the EVM TOML (if
   its block time exceeds `2s`) or a recorded acceptance. This is the scale test for the config
   tooling.
3. **Balance monitoring is a separate handoff.** It is not a cutover gate. Executor funding and
   transaction receipts were validated during each wave; P9 compiles all standalone transmitter
   addresses for monitoring. Alert ownership and thresholds are decided outside this migration effort.
4. **Small waves are proven; keep deriving the budget.** Node 0 was the canary, followed by
   nodes 1–5, 6–10, and 11–15 only after each prior wave passed. The last wave contains active
   nodes 16, 17, 18, and 20. Committee membership is not uniform across the 61 EVM chains, so
   recalculate the simultaneous-outage budget from each affected chain's live members and threshold;
   do not assume the old 16-member, threshold-9 shape or treat its budget as an entitlement to
   overlap blind windows. Keep windows short on fast chains.
5. **Record the exact image; use a release before prod-mainnet.** The staging and current
   prod-testnet waves deliberately run the staging-proven
   `45c7148eaaa84fe6cc73f9baa4de12612971c665-rc` image. Do not silently substitute a newer RC.
   Before external prod-mainnet, select and validate the release-tagged image (`vX.Y.Z`) operators
   will receive, including the migration tooling and required fixes.
6. **No secondary committee.** Staging's node-0 complication does not exist here. The initial
   assumption that nodes 16–20 were all idle was wrong: four have EVM roles, while node 19 is idle
   and is retired without a standalone replacement.

## Hard rules (unchanged from staging)

1. Node 0 was the canary. Continue in at-most-five-node waves only after clean validation of the
   previous wave; derive the safe budget from live committee size and threshold.
2. Export while the node is up; stop the node before the standalone verifier starts. One
   JD record cannot have two owners.
3. Never boot the verifier without its `[key_import]` block.
4. The `signer_address` in the node's new verifier job must equal `$EXPECTED_ID`.
   `ApplyVerifierConfig` is offchain-only, so that field is where a wrong key shows. Stop.
5. After the standalone verifier job first starts, re-apply and confirm the disabled flag
   for any chain that was disabled on the node before the cutover.
6. From P1 on, every EVM `apply-verifier-config` input sets `consolidateAggregators: true` and
   leaves `revokeOrphanedJobs: false`.
7. The current waves preserve exact executor specs with `jd_propose_job`; reconcile their metadata
   before state generation or later executor updates. With tooling including #1590,
   `apply-executor-config` can route by `executor_node_name` or `ExecutorNodeID`, but must never
   fall back to the verifier's alias. See staging steps 7 and 9.

## Conventions

Every command below assumes this block has been pasted into the shell. AWS SSO expires
every 8h.

```sh
aws sso login --sso-session griddle-session

# Current kubeconfig context names; adjust if your profile prefix differs.
export CTX=griddle-platform-ccip-prod-teamccipadmin       # cluster reads, exec, scale, approved Secret deletion
export CTX_ENG=griddle-platform-ccip-prod-teamccipengineer # secret creation (create, not patch)
export NS=chainlink-ccv-testnet

CCV=~/dev/dev2/chainlink-ccv
CLD=~/dev/dev2/chainlink-deployments
DEPLOY=~/dev/dev2/chainlink-ccv-deploy
EVM_VALUES=$DEPLOY/deploy/config/prod-testnet/committee-verifier-evm/config.yaml

# per cutover; i is an active node in 0..18 or 20 (node 19 is retired)
i=1
NODE=ccv-prod-testnet-$i                    # JD alias, topology alias
CL=chainlink-ccv-testnet-$i                 # the node's k8s deployment, service, secret prefix
VER=committee-verifier-evm-$i               # verifier: release = Deployment = JD node name
EXE=executor-evm-$i                         # executor: same three names
EXPECTED_ID=<from P8>                       # this node's OnchainSigningAddress from JD
```

Deploys are IssueOps, as in staging: branch in chainlink-ccv-deploy, PR (ready, not
draft), comment `.deploy prod-testnet` on it, and approve the confirmation. There is no
auto-deploy on merge. The command targets only `chainlink-ccv-testnet` in `us-west-2` by default;
append `| --region=us-east-2` when deploying that region. There is no `.deploy prod` command:
prod-testnet and prod-mainnet are deployed separately. The PR must be approved and its
`validate-config-decode` check must pass.

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

**Completed for EVM nodes 0–18 and 20; do not rerun.** Each node originally ran two
`ccvcommitteeverifier` jobs with verifier IDs `aggregator-1-default-verifier` and
`aggregator-2-default-verifier`. The consolidated job uses `default-verifier`, while the legacy
IDs remain aggregator `secret_name`s. Every consolidated proposal was approved before the two old
proposals were cancelled in Feeds Manager.

For any future initial consolidation, use staging P1's corrected input with
`consolidateAggregators: true` and `revokeOrphanedJobs: false`, scoped by `targetNops`. JD cannot
revoke the approved legacy jobs, and enabling revocation can drop datastore records even though
the jobs remain live. Record disabled chains first, approve the new job, cancel the old proposals,
then restore the disabled flags under the new verifier ID.

### P2. Images

The current prod-testnet waves use the staging-proven
`45c7148eaaa84fe6cc73f9baa4de12612971c665-rc` image for both components. Keep the full 40-character
SHA and verify both private ECR repositories before deployment. Do not silently change images
between activation and validation.

Before prod-mainnet, replace this with the exact release tag (`vX.Y.Z` from
`release-publish.yaml`) selected for operators and repeat the migration checks from that tag. For
the current RC, create the tooling worktree used by staging steps 2 and 3 with:

```sh
IMAGE_SHA=45c7148eaaa84fe6cc73f9baa4de12612971c665
CCV_IMG=/tmp/ccv-image-prod-testnet
git -C $CCV fetch origin
git -C $CCV worktree add --detach $CCV_IMG $IMAGE_SHA
```

### P3. Charts and config dirs

The charts already exist and are shared with the Solana and Canton releases:
`committee-verifier-base` for the verifiers and `executor-base` for the executors. Create the
prod-testnet value trees:

- `deploy/config/prod-testnet/committee-verifier-evm/`: common, config, per-instance values.
- `deploy/config/prod-testnet/executor-evm/`: the same three.

Model them on the staging trees; the only intended differences are environment labels,
the image tag (P2), the per-node `keyImport.expectedId` (P8), and resource sizing if
staging's soak showed a need. Everything staging P3 lists carries over unchanged: probes on
bootstrap `/health` (9988) with a `startupProbe`, `strategy: Recreate`, no PDB, no
ServiceMonitor, `[key_import]` rendered from `keyImport.expectedId`, and the loopback-only admin
console (`adminConsole`). After step 9, check
bootstrap `/ready` on 9988 and the app `/health` on 8100/8101.

### P4. Databases (3 per migrating node, on the node's own cluster)

Verifier-bootstrap, verifier-app, executor-bootstrap per node; they cannot share (goose
version table). Each migrating node gets its own cluster,
`chainlink-ccv-testnet-evm-standalone-$i`, in
`deploy/config/prod-testnet/database-provisioner/database-provisioner.yaml`, modeled on
staging's: 20 clusters and 60 databases for the 20 active nodes; idle node 19 gets neither.
Not on `chainlink-ccv-testnet-dons`, for the same two-way isolation as staging (the rollback
path never depends on the new clusters), and not on one shared cluster. A shared database
failure could otherwise remove enough signers on an affected chain to stall attestations.
That is the exposure the DON cluster carries today for all 21 nodes. Per node, an incident
costs one signer.

Sizing: start each at a single `db.t4g.medium`, the shape of the 24 Solana and Canton
clusters already in that file (one per verifier or executor), and revisit after the first
soak with real traffic. The DON cluster's 2× `db.r8g.xlarge` on aurora-iopt1 is not the
reference: it carries the CL nodes' LogPoller, which the standalone verifier does not run
while it reads source logs over RPC. Map keys ≤ 43 chars; set `connectionSecret.name`
explicitly.

If the standalone LogPoller reader is turned on here (it needs the standalone-format EVM
config; see the go/no-go), its `evm` schema adds the LogPoller's blocks and 30 days of
`CCIPMessageSent` logs per OnRamp, 61 chains per node, to the database named by `[db].url`
in the EVM secrets file. That database then dominates the other three; size each node's
cluster, and its backups, for it before enabling the reader. See
[Source logs](../verifier/evm-standalone.md#source-logs-rpc-or-a-logpoller).

### P5. Per-chain config review at 61-chain scale

For each of the 61 EVM chains: run `ccv migrate inspect-config` against the node EVM
TOML (both the `chainlink-ccv-testnet` values and the committee currently list 61) and record
accept-or-correct for every warning and every chain's `txm_block_time` /
`txm_block_time_source` (`operator`, `curated_chain_default`, or
`generic_fallback`). Unconvertible `[[EVM]]` entries are reported under `failed_chains`
(and boot-time `chainaccess.CheckDeclaredChainCoverage` rejects any declared `[[chains]]`
entry that is missing or in `failed_chains`), so `failed_chains` must be empty for all 61
committee chains. This is one recorded review, reused across nodes, re-run when the
config changes.

Chain-level settings carry over from the node TOML, over the same chain defaults the `ccip` image
resolves, so most chains produce no warning. Compared setting by setting against the current DON
config (`chains.yaml` + `rpcs.yaml`, 63 chains), and leaving aside what standalone fixes on every
chain (heads in memory, TXM v2, no log broadcaster or balance monitor), one chain runs differently,
and the conversion warns on four:

- Scroll Sepolia (534351): AutoPurge turned off. Its chain defaults use Scroll's detection API
  with no `Threshold`, which TXM v2 cannot run; with it on, the executor could not transmit there.
- Polygon Amoy (80002) and chain 157: `BalanceMonitor.Enabled = false`. Executor funding uses the
  separate external balance-monitoring handoff instead.
- Chain 9746: `LogBroadcasterEnabled = false`; nothing standalone runs reads it.

Any other warning on a later run is new and needs a decision.

### P6. Secrets per node

As in staging P6: three TOMLs per node (verifier bootstrap, verifier app with the
aggregator HMACs under the P1 `secret_name`s, executor bootstrap), DB URLs composed from
the P4 connection secrets, created via `$CTX_ENG` with `-v1` naming. Delete all three local TOMLs
immediately after the runtime Secret creates succeed, as shown in staging P6. The verifier also
needs its key-import secret. Validate every secret. Keep the verifier bootstrap database and its
keystore password as the durable recovery copy after import; do not add the temporary export or its
plaintext export password to routine backups.

The prod-testnet CL database was deleted with `skipFinalSnapshot: true` in
[chainlink-ccv-deploy#543](https://github.com/smartcontractkit/chainlink-ccv-deploy/pull/543); it is
not a rollback copy. After the temporary migration copies are disposed, the standalone bootstrap
database, its recovery backups, and its keystore password are the only signer recovery path. Follow
staging step 11 for export unmounting, canary verification, approved Secret deletion with the
`TeamCCIPAdmin` context, and disposal of password-manager entries created under the earlier
instruction to preserve export-password backups.

### P7. Griddle releases, both components initially at zero replicas

As in staging P7, in the `prod` section of `griddle.yaml` with `ccip_env: prod-testnet`:
`committee-verifier-evm-$i` and `executor-evm-$i` per migrating node. Start both at
`replicas: 0` while the databases and all three runtime/key-import secrets are prepared;
the verifier must never start without its key-import secret (hard rule 3). Once those gates
pass, move both to one replica and add the legacy node to maintenance mode in the same deploy.
Add releases per batch, not all upfront.

### P8. expected_id per node, from JD

```sh
cd $CLD
go run ./domains/ccv/cmd jd node list -e prod_testnet -f json
go run ./domains/ccv/cmd validate nop-support -e prod_testnet
```

Record each node's `OnchainSigningAddress` (`$EXPECTED_ID` in step 3) and current CSA
key (rollback). `nodes.json` also holds standalone Canton and Solana records; do not touch those
records when adding EVM executors.

### P9. Funding source and monitoring handoff

Inventory available funds per network and fund each new executor conservatively from the migration
wallet or accessible legacy transmitter balances. The working target is 0.15 native token per
supported chain, with every receipt and resulting balance recorded. Validate a funded source and
destination lane for each executor; pool execution alone does not prove its transmitter.

If a faucet top-up is separately approved, use the [Internal Faucets API](https://smartcontract-it.atlassian.net/wiki/spaces/dapp/pages/585924700/Internal+Faucets+API)
with `activeNetwork` and `nativeTokenToSend`, request only the native-token shortfall, and never
retry empty or unsupported faucets blindly. **Do not use faucet or bridge work to solve the
pre-existing zero/dust gaps already accepted in #21167 and #21168.** Record remaining gaps
explicitly rather than hiding them behind an aggregate success count.

Balance monitoring is separate from migration. Do not block job delivery on alert setup. Hand off
the following standalone transmitter set to the balance-monitoring owners. Each address needs
per-chain balance and transmit-failure coverage; alert ownership and thresholds remain open.

### Standalone transmitter monitoring handoff

| Node | Standalone executor transmitter |
|---|---|
| 0 | `0x616d623b43DDf35608312636e174365F53232523` |
| 1 | `0xc2b7d8e10DF3EF611bE3a059F0cfa246830f9145` |
| 2 | `0x9Bd7C2Dc0B5504Cf70Db51c9EfCfFb0EB8B72771` |
| 3 | `0xfcbA883D1448CBFcB3F0e6bf510eec7E4ce5a75f` |
| 4 | `0x33aa94da661e11dfCb7E25F3a7681842Daf7fb87` |
| 5 | `0xc5e797d07852622edCD2514e309A5f03FBb602CC` |
| 6 | `0xf5B45428FF08DF17A7f99e32d0593FEbb2419108` |
| 7 | `0x977a180b6bA93E970D6a940217bB3b02cf4288a1` |
| 8 | `0xdb70898790D26830e5398C8d41063f9b2eb3246f` |
| 9 | `0x6bC1574fF82b0D2b6cdF50ee26B93c50c9a13E9D` |
| 10 | `0xd642B66d3c83262625C1574C307043e0b4804B50` |
| 11 | `0xf2EED7BB49327F3f33095E69a3fCeba74A65dBAf` |
| 12 | `0xC12ad853B8793B91395752D42ceb14bA31B4f290` |
| 13 | `0x6AC18172965159a88f2D468b2Cb0ffAD204E1Af6` |
| 14 | `0x2578102Ef5e9031743aD71113a485C71f73Cc859` |
| 15 | `0x3e796226720820fbf2aB96b96a539cb6F0D2Acf3` |
| 16 | `0x29efea96B257082A53c14667CEB567F285bF69C0` |
| 17 | `0x16d6525dcf06843Eb48910ED5429B88d8aE83567` |
| 18 | `0x98CA314E478D16253107547eD6447EC99E0E47Ca` |
| 20 | `0x7A5fb6B203c552f5430208313a23567061063BF3` |

The active-four addresses were collected from the healthy standalone bootstraps after #545;
their intended-transmitter execution evidence is linked in "Execution status". Those receipts
prove the targeted lanes, not full per-chain funding coverage. Earlier per-wave funding evidence
and accepted gaps are recorded in
[chainlink-deployments #21167](https://github.com/smartcontractkit/chainlink-deployments/pull/21167),
[#21168](https://github.com/smartcontractkit/chainlink-deployments/pull/21168), and
[#21169](https://github.com/smartcontractkit/chainlink-deployments/pull/21169). Do not infer
per-chain coverage from an aggregate transfer count.

## The cutover, per node

Execute the staging plan's per-node procedure (steps 1–12) with these substitutions and
additions:

| Staging reference | Prod-testnet form |
|---|---|
| `staging_testnet` env / `griddle-platform-ccip-stage-*` contexts | `prod_testnet` / `griddle-platform-ccip-prod-*` |
| `chainlink-ccv-staging-$i` / `chainlink-ccv-$i` | `ccv-prod-testnet-$i` / `chainlink-ccv-testnet-$i` |
| `flux suspend helmrelease chainlink-ccv` | `flux suspend helmrelease chainlink-ccv-testnet` |
| `maintenanceMode.specificNodes` in staging `overrides.yaml` | same mechanism in `deploy/config/prod-testnet/chainlink-ccv-testnet/overrides.yaml` |
| five testnets for funding and balance checks | the node's ~61 chains (script the balance check; manual does not scale) |
| step 11 confirmation message on a staging lane | a real lane this node verifies; announce the window first |
| soak: manual balance check | soak: final balance evidence, TXM v2 metrics, transmit-failure review; monitoring handoff at the end |

Every completed batch passed both-aggregator signing, intended-executor execution,
disabled-chain, health, and metadata checks before the next wave. The active-four wave
(16, 17, 18, and 20) passed the same gates after #545 and
[CLD #21317](https://github.com/smartcontractkit/chainlink-deployments/pull/21317). Idle node 19
stopped with the legacy release and has no standalone job to activate. See "Execution status"
for the final activation, reconciliation, and decommissioning records.

## Validation before calling it done

Every item from staging's validation, here under real traffic:

- **Canary restart under traffic (mandatory):** delete an executor pod mid-flight on a
  busy chain and watch TXM v2 recover — 90s nonce-gap wait, fee-bumped replacements, no
  stuck message. This is the production gate from the TXM v2 assessment; staging's run
  was rehearsal, this one counts.
- **Head-tracker cold start** on a busy chain: measure the re-sync cost under real head
  velocity; decide acceptability. The head tracker starts cold whichever reader runs, and a
  LogPoller-backed chain also replays about one finality depth from its checkpoint on every
  start, so measure both if any node turns the LogPoller on.
- **LogPoller reader, if any node turns it on:** that node runs a different source reader
  than the rest, so spot-check it before the go/no-go, put
  `verifier_source_reader_last_processed_finalized_block` against the chain head on a
  dashboard (a stalled LogPoller pins the reader's heads), and confirm a restart's replay
  finishes in reasonable time.
- **Rollback drill:** repeat once here even though staging drilled it — the prod contexts
  and release names differ, and the people on the prod-mainnet rotation should run it.
- **Dashboards:** source-reader head gauges, critical-invariant counter, OffRamp read latency,
  transmit failures, and the TXM v2 metric names (`txm_num_broadcasted_transactions`,
  `txm_num_confirmed_transactions`, `txm_num_nonce_gaps`, `txm_time_until_tx_confirmed`).
  Keep final balance evidence for the separate monitoring handoff.
- **Full-fleet soak:** two weeks, all 20 active nodes standalone after the final activation,
  before the go/no-go.

## Go/no-go to prod-mainnet

Operator comms for prod-mainnet may start when all of these hold:

- [x] The first 16 EVM-serving nodes cut over and confirmed: a message per lane, each node's
      job `signer_address` equal to its P8 address, and each executor's transmitter
      landing transactions.
- [x] The remaining active four cut over and confirmed in #545 and
      [CLD #21317](https://github.com/smartcontractkit/chainlink-deployments/pull/21317), including
      both-aggregator signing, intended-transmitter execution, and disabled-chain restoration.
- [ ] Two-week full-fleet soak with no sev and no unexplained transmit failure. It began on
      2026-11-11 and completes no earlier than 2026-11-25.
- [ ] Canary restart and rollback drill results written down, plus the standalone transmitter
      monitoring list handed off separately. The 20-address list is compiled in P9; alert ownership
      and thresholds remain open.
- [ ] The per-chain config review (P5) archived; every deviation has an owner.
- [ ] Source-read mode for prod-mainnet decided and documented in the [standalone reference](../verifier/evm-standalone.md#source-logs-rpc-or-a-logpoller):
      `eth_getLogs` from the node TOML, or the standalone LogPoller, which needs the
      standalone-format EVM config, an EVM secrets file, and database sizing for its logs.
- [x] Every executor has canonical `standalone`/`appConfig` metadata and a persisted JD node ID;
      regenerated NOP state includes it and telemetry authorization succeeds. The active-four
      reconciliation completed in #21320 and the scoped state generation covered all 20 nodes.
- [ ] Exercise a later scoped `apply-executor-config` against a reconciled executor record and
      confirm explicit routing by `executor_node_name` or `ExecutorNodeID` (#1590), without changing
      the preserved job name, external job ID, executor ID, or pool membership.
- [ ] The prod-mainnet image is a validated release tag, not the prod-testnet RC.
- [x] Runbook corrections from this environment fed back into this PR and
      [node-ops-wiki #487](https://github.com/smartcontractkit/node-ops-wiki/pull/487); both
      documentation PRs remain subject to review and merge.

## Open questions

1. *(Resolved)* **Nodes 16..20.** The earlier assumption that all five were idle was wrong:
   49 of the 61 EVM chain configs include nodes 16, 17, 18, and/or 20. Migrate those four
   and retire idle node 19 without a replacement. The resulting allocation is 20 standalone
   clusters and 60 logical databases, not 21 clusters and 63 databases.
2. *(Resolved)* **`storage_locations` listed `aggregator-1.testnet.ccip.chain.link` twice.**
   [CLD #21270](https://github.com/smartcontractkit/chainlink-deployments/pull/21270) corrected
   the second entry to `aggregator-2.testnet.ccip.chain.link`; the separate `aggregators` block
   was already correct.
3. *(Operational, tracked per wave)* Funding sources and remaining gaps are recorded in each wave's
   activation PR. Use available funds conservatively, validate funded lanes, and do not reopen the
   explicitly accepted nodes 1–5 gaps with unapproved faucet or bridge work (P9).
4. *(Resolved)* The node values and committee both list 61 EVM chains (P5); re-check this
   comparison whenever either side changes.

## What prod-testnet does not decide

External operator scheduling and comms, the HSM/KMS path for operators whose keys cannot
be exported, the NOP funding model (each prod-mainnet operator funds their own executor),
prod-mainnet batching under external windows, and public image publishing approvals
(F2/F3 in the epic). Those belong to the prod-mainnet program, which the go/no-go above
gates.
