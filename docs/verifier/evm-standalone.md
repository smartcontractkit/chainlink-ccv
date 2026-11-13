# EVM standalone verifier and executor

This document describes EVM standalone architecture, configuration conversion, source readers, and health endpoints. It is a technical reference, not a scheduled cutover procedure.

The executor's transaction-manager choice and recovery tradeoffs are covered in the [TXM v2 assessment](../migration/txm-v2-assessment.md).

## Architecture

| Component | CL mode | Standalone |
| --- | --- | --- |
| Onchain signing key | OCR2 EVM key bundle on the node | The same key, imported into the verifier's bootstrap database |
| Transmitter | One EVM account per destination chain | One fresh key generated and funded by the executor operator |
| CCV jobs | Two jobs on one node | One job on each of two processes |
| JD node record | One record for both jobs | Two: the verifier adopts the existing one and the executor is new |
| CSA key | The node's | Each process generates its own |
| EVM RPC config | The node's TOML | The same file, read directly |
| Telemetry | The node's own | Each process exports to an OpenTelemetry sidecar, authenticated with its CSA key |
| Database | The node's Postgres | One bootstrap database per process, plus the verifier application database |
| Source events | `eth_getLogs` per poll, or the node's LogPoller | `eth_getLogs` per poll by default; the verifier's own LogPoller is opt-in per chain |

Standalone keeps CL mode's 2-second NTP retry backoff and 24-hour indexer message-deduplication window. `source_backoff_duration` controls failed Indexer requests only; changing it does not change NTP recovery timing.

The standalone bootstrapper validates each job proposal, starts the job, and calls `ApproveJob` itself. Operators do not accept standalone jobs in the JD UI.

## Key migration

The OCR2 bundle's onchain signing key is the address in the `CommitteeVerifier` signer set. The node publishes it to JD as `OnchainSigningAddress`. Reusing that key avoids a signer-set configuration transaction on every chain. `TestE2EMigration_CLToStandalone` asserts that the signing address remains unchanged across export and import.

`ccv migrate export` supports a node running exactly one `ccvcommitteeverifier` job. Consolidate multiple verifier jobs before export rather than choosing one. The command writes an encrypted OCR2 key bundle, its plaintext export password, and a verifier `[key_import]` snippet. The encrypted bundle is not a raw private key, but anyone with both files can decrypt and use the key. Treat both as private-key material, keep them off shared storage, and never send them to Chainlink Labs.

Only the verifier imports the OCR2 EVM signing key. The executor generates a fresh transmitter; nothing onchain names that transmitter, so it needs funding but no signer-set change. The executor publishes its own address on its JD chain configs, and the operator's funding confirms the intended account. Each process also generates its own CSA key for JD authentication. CSA private keys are not exported.

The `expected_id` in `[key_import]` makes a wrong-node mount fail at boot. The export tool fills it from the registered signing address rather than asking an operator to transcribe it. The verifier also compares its keystore address with the job's `signer_address` and refuses to run on a mismatch.

The import runs only when the key is absent. On later restarts, the export and password files are not read, but `expected_id` is still checked against the stored key. Keep the `[key_import]` block after removing the export mounts: if the bootstrap database is lost, it makes the verifier fail to start rather than generate a new signing identity. Do not remove `expected_id`; it contains only the public address and remains the wrong-key safeguard.

Back up and persist both bootstrap databases and their keystore passwords. The verifier bootstrap database holds the imported signing key; the executor bootstrap database holds the only key to its funded transmitter.

### Dispose of temporary migration key material

After the cutover, remove the export mounts from one verifier, restart it, and confirm `key already exists, skipping import`, the unchanged public signing address, and accepted signatures at both aggregators. Only then dispose of that verifier's temporary export. Repeat the same proof for each additional verifier you operate; a single-verifier operator needs no further rollout. Removing mounts does not delete the Kubernetes Secret or any operator-held copies.

Delete the named `ocr2.json`, `export-password.txt`, and `verifier.key_import.toml` files on every host that received them, then remove their empty migration directory with `rmdir`. Include the node and verifier hosts and any workstation or staging directory used to copy them. If `rmdir` reports remaining files, stop and inventory them rather than recursively deleting the directory. Delete any password-manager entry created for the export password, including retained old versions, without printing its contents. Do not put the temporary export or its plaintext password into routine backups. For Kubernetes, check references and deletion protection, then delete only the specific key-import Secret after approval, using a role with explicit Secret-delete permission or a platform request.

If these files or passwords were copied into a secret store, backup, or snapshot, track each such copy through deletion or approved retention expiry with the infrastructure owner. Ordinary deletion does not prove erasure from a restorable copy; record any outstanding retention date instead of declaring disposal complete early.

The old Chainlink database and backups hold another copy of the signer. Their disposal is a separate, approved decommissioning step after the rollback window and a verified standalone backup. Do not delete the active verifier bootstrap database, its recovery backups, its keystore password, or the executor's database in an attempt to remove migration material. The operational signing key necessarily remains available to the standalone verifier and its recovery system.

The standalone verifier declares its chains in bootstrap config and reports them to JD on connect. `ApplyVerifierConfig` and `ApplyExecutorConfig` require that registration before proposing a job. `ApplyVerifierConfig` also persists the alias-to-signer mapping in environment state (`nopSigners`) for chain families whose standalone verifiers do not report chain configs.

The CSA key has no onchain meaning. During migration, JD repoints the existing node record to the verifier's new CSA key and registers a separate record for the executor. This retains the verifier's node ID, NOP alias, and job history without copying the old CSA private key. A process cannot repoint its own record: it cannot authenticate as that record until the record carries its key, and its connection update contains chain configs, not a replacement public key.

`ApplyExecutorConfig` routes a standalone executor job to that separate record when the NOP declares `executor_node_name`, or when its input supplies `ExecutorNodeName` or `ExecutorNodeID`. Without one of those references, it requires complete metadata from a previous canonical standalone proposal or `ReconcileJobsWithJD`; it must not fall back to the verifier's NOP alias. A generic `jd_propose_job` can deliver the initial exact-spec migration job, but its metadata must then be reconciled from JD so later executor updates route correctly.

The old Chainlink node must be stopped before the standalone verifier starts because one JD record cannot have two owners. Two records are a property of standalone mode, not a migration duplicate: the verifier adopts the existing record and the executor gets a new one.

## EVM config conversion

The `[[EVM]]` and `[[EVM.Nodes]]` sections are translated at startup and chain IDs resolve to chain selectors. Every other section is ignored and named at startup and in the `ccv migrate inspect-config` report's `ignored_top_level_sections`.

Reusing the node TOML preserves chain-level settings for gas estimation, node pools, head tracking, finality, chain type, and RPC error patterns over the same defaults the node used. Those defaults have two layers embedded in the verifier and executor: chainlink-evm's built-in defaults and CCIP's overrides (`ccip/config/evm` in the chainlink repo). This is the pair a Chainlink `ccip` node image runs through `CL_CHAIN_DEFAULTS=/ccip-config`.

A core node image with `CL_CHAIN_DEFAULTS` empty uses chainlink-evm's built-ins alone and can differ on settings its config does not pin. Standalone always resolves the CCIP pair. Do not set `CL_CHAIN_DEFAULTS` on standalone containers: chainlink-evm then loads that directory instead and exits at startup on a file it cannot decode, while the embedded defaults skip such a file with a warning.

Per-node `Order` carries over, preserving RPC prioritization. A node with no `Order` stays at the pool's lowest priority.

Standalone fixes a few chain-level settings because its runtime has no other mode:

- Heads stay in memory (`HeadTracker.PersistenceEnabled = false`).
- The log broadcaster and balance monitor are off.
- Transactions use TXM v2 without forwarders or dual broadcast.
- `KeySpecific` entries are dropped because they name the node's old keys and cannot match the executor's new key.
- `Transactions.AutoPurge` without a `Threshold` is disabled because TXM v2 cannot run detection-API mode.

A conflicting setting produces a startup warning. An unrecognized or undecodable setting, or one chainlink-evm rejects, is dropped by name and the chain starts with everything else. An `[[EVM]]` block whose `ChainID` does not decode is skipped while other chains still start.

If the node config sets no TXM v2 block time, the value comes from a curated per-chain table when the chain's real block interval exceeds the two-second floor upstream validation enforces. Otherwise, the generic two-second fallback applies. The `ccv migrate inspect-config` report's `txm_block_time_source` reads `operator`, `curated_chain_default`, or `generic_fallback`. A process that writes to a chain logs the source when that chain's TXM starts. Review any `generic_fallback` on a slow chain and set an explicit value. The [TXM v2 assessment](../migration/txm-v2-assessment.md) explains the cadence and recovery tradeoffs.

Send-only nodes and per-node `HTTPURLExtraWrite` and `IsLoadBalancedRPC` have no standalone equivalent and are dropped. Other per-node settings beyond endpoint URLs, name, and selection order are also dropped and named at startup. An operator relying on a send-only endpoint should add it as a full node.

## Declared chain coverage

The bootstrap config's `[[chains]]` entries declare the chains the operator runs and registers the signing key in JD. Every EVM entry is checked against the mounted EVM config at boot without network calls.

A declared chain stops startup with an error naming the chain, selector, and reason when:

- Its section is missing.
- Its section fails to convert because it has no usable RPC endpoint or an unknown chain ID.
- Its section cannot serve the chain because it has no RPC nodes or chainlink-evm rejects its settings.

Inside conversion, an unservable chain is skipped and reported under `failed_chains` so an old unused `[[EVM]]` block does not take down every other chain. Declaring that chain in `[[chains]]` makes the same problem fatal. A chain present in EVM config but not declared sits unused unless a job spec references it.

## Finality checking

The job spec accepts `disable_finality_checkers`, but only standalone mode honors it; CL mode ignores it and always runs finality checkers. Do not set it on an EVM migration job: the node never disabled checking, so the cutover must not either. The field exists for chain families whose standalone deployments predate EVM migration.

## Source logs: RPC or a LogPoller

A CL-mode verifier reads `CCIPMessageSent` logs through the node's LogPoller when `[Feature] LogPoller = true`, and uses its finality signal in place of the header-based finality checker. Otherwise it issues `eth_getLogs` per poll.

The standalone verifier uses RPC by default: ranges of at most 100 blocks, fed by the in-memory head tracker. A lower node-config `LogBackfillBatchSize` caps the range, and a lower `RPCDefaultBatchSize` caps the header batch below its default of 25. Each poll re-reads the chain's unfinalized window, so call count grows with finality depth.

The standalone verifier can run its own LogPoller per chain. It is off by default and exists only in standalone-format EVM config, not node TOML:

```toml
[chains.<selector>]
log_poller_source_reader_enabled = true
```

It also needs an EVM secrets file (`EVM_SECRETS_PATH`, default `/etc/evm/secrets.toml`) whose `[db].url` names the database for the LogPoller's `evm` schema. This can be the verifier application database or a separate one; the schema and version table do not collide with the verifier's. The process refuses to start if a chain enables the reader and `[db]` is missing. With node TOML mounted, every chain reads over RPC even if the old node ran its LogPoller.

LogPoller tables do not migrate. The standalone verifier starts without a checkpoint and its first scan begins 500 blocks behind the finalized head. Messages finalized after the old node stopped but before that block are not read by this verifier, whichever reader it runs. The lookback is well over an hour on a 12-second chain but only a few minutes on a sub-second chain. Schedule cutovers so the remaining committee stays safely above threshold, and keep overlapping verifier windows short.

When the standalone LogPoller is enabled:

1. **Every start replays.** Startup takes the EVM database lease, waits until the checkpoint is finalized, registers the filter, and replays from the checkpoint, normally about one finality depth. The chain reports not ready until replay finishes. Confirm `Executing replay finished` in the LogPoller log for the requested start block.
2. **Size the database for chain data.** It holds the LogPoller's blocks and 30 days of `CCIPMessageSent` logs per OnRamp. Size backups accordingly.
3. **Use one writer per EVM database.** A second process waits on the lease and its LogPoller chains stay not ready until the first releases it.
4. **Recovery reads LogPoller tables.** A checkpoint rewound with `chain-statuses set-finalized-height` is refilled over RPC by the next start's replay. A live replay older than log retention reads nothing. A chain disabled by a LogPoller finality violation is not recovered by `reset-reader` or `replay`; follow [Resolving a Finality Violation](../runbooks/resolving-finality-violation.md).
5. **A stalled LogPoller pins reader heads.** Watch `verifier_source_reader_last_processed_finalized_block` against the chain head. Standalone also reports `source unhealthy` on `/health` when the LogPoller is unhealthy; CL mode does not.
6. **Disable it before rolling back to an older image.** Older binaries reject `log_poller_source_reader_enabled`. The `evm` schema's migrations are forward-only, like the verifier's own.

## Transaction safety during cutover

The standalone executor reads each message's onchain execution state before executing, so anything the old node already landed is skipped. The gap is a transaction the node submitted that has not confirmed: the state read still says unexecuted, so standalone can submit its own attempt from its own account. One lands and the other reverts, which wastes a transaction but does not double-deliver the message. Draining the old node's queue before shutdown avoids that race.

## Health and readiness endpoints

Each standalone process serves bootstrap and application HTTP servers, plus the optional admin console when `/etc/ccv-admin/config.toml` is mounted. Keep all of them private; the bootstrap server also exposes keystore reader endpoints.

The bootstrap server listens on `listen_port` from bootstrap config. Its endpoints concern process and job lifecycle, not component health:

- `/health` is a static 200. It says the process is up and serving, nothing more.
- `/ready` is 503 until the job's Start has returned, then 200. It returns to 503 while a job stops or is replaced. A component can fail after Start without changing `/ready`.
- `/keystore/reader/getkeys` returns public keystore payloads for service registration.
- `/keystore/reader/getaddresses` returns the EVM address of a secp256k1 key.
- `/health/live` is a static `alive` endpoint for standard probes.
- `/health/ready` is equivalent to `/ready`.

This server starts only after bootstrap database migrations, keystore setup including key import, and JD lifecycle start. On restart, lifecycle start also starts the cached job. JD connects in the background, so the server can come up before JD registration completes.

The application server carries the real health signal. By default, the verifier listens on 8100 and the executor on 8101; each job's app config can override its port with `http_listen_port`.

Its `/health` returns:

- 200 with `status: "ready"` when healthy.
- 200 with `status: "degraded"` and the skipped component named when some functionality is unavailable.
- 503 when no usable chain or component remains.

Degraded can be expected during startup or for intentionally unsupported chains, so read the component report. It also names a verifier chain whose log scans or finality checks keep failing beyond the staleness threshold, and `jd.UpdateNode` while JD has not accepted chain configs.

The verifier also serves `/stats`. Application and chainlink-evm metrics export through Beholder/OpenTelemetry; scrape the telemetry sidecar's Prometheus endpoint rather than adding an application-port `/metrics` endpoint. A stalled LogPoller additionally needs the head-progress check described under [Source logs](#source-logs-rpc-or-a-logpoller).

The optional admin console defaults to `127.0.0.1:8105` and has its own `/healthz` liveness endpoint. Both services expose the active job at `/job` and sanitized effective chain configuration at `/chains`; the executor also exposes transmitter balances at `/transmitter-keys`. Verifier search, recovery, and action-log routes are not registered on the executor. See the [admin console guide](admin-console.md).

For Kubernetes, probe the bootstrap port. The application server starts only after JD proposes the job, so an application liveness probe restarts the pod until then and an application readiness probe holds every rollout. Use bootstrap `/health` or `/health/live` for both probes and add a startup probe with a few minutes of budget. Monitor application `/health` and bootstrap `/ready` separately because the probes cannot see later component failures. Run one replica with a `Recreate` update strategy: a rolling update briefly runs two processes on one signing or transmitter key.

## Current limits

- The verifier application database persists chain statuses and queues separately from bootstrap. EVM head-tracker and TXM state remain in memory, so a restart starts the head tracker cold and re-syncs from RPC. TXM restart recovery has the additional risks described in the [TXM v2 assessment](../migration/txm-v2-assessment.md).
- The standalone LogPoller reader can only be enabled in standalone-format EVM config. Mounting node TOML uses RPC source reads even when the old node ran its LogPoller.
