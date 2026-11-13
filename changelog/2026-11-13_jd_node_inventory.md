# Persist the CCV JD node inventory in environment metadata

CCV deployment changesets now snapshot the Job Distributor node inventory into native CLD
environment metadata under `offchainConfigs.jdNodes`. This gives o11y and deployment tooling one
durable source for node identity without reconstructing nodes from job specs, node names, or
on-chain signer addresses.

## Recorded data

The inventory is queried from JD with exact `product` and `environment` label selectors and is
keyed by JD node ID:

```json
{
  "offchainConfigs": {
    "jdNodes": {
      "node_8g6Z89PFNiV9HQ1wAmBed": {
        "name": "executor-evm-0",
        "csaKey": "6e21c26e84707e34f1faff31787a97ed9ba93f336d8073a75124860d276ef6ce",
        "labels": {
          "environment": "prod_testnet",
          "product": "ccv",
          "target": "executor-evm-0",
          "type": "plugin"
        }
      }
    }
  }
}
```

Only public identity and labels are stored. Connection state, timestamps, node version, private
keys, and other volatile or sensitive fields are deliberately excluded. No role or chain family is
inferred from a node name or chain-config response; consumers can use JD labels such as `target`.

## Update paths

The same snapshot helper is used by:

- JD node registration and the standalone node-save changeset;
- verifier and executor job proposal management;
- proposal-status synchronization after job acceptance;
- approved standalone executor reconciliation.

Each successful call replaces the complete JD inventory snapshot, so renamed keys and labels are
refreshed and removed JD records do not remain indefinitely. An empty or invalid JD response fails
the changeset instead of erasing a previously usable snapshot.

The inventory remains compatible with CLD's normal durable-pipeline flow: changesets return the
updated datastore, the pipeline saves it as an artifact, and the normal datastore merge persists it
to `env_metadata.json` or catalog storage. The registration changesets continue writing
`nodes.json` for the existing CLD node-ID allowlist.

## Persistence fixes

Combined verifier/executor execution now feeds the verifier datastore output into the executor
changeset instead of applying both against the same stale input. Devenv proposal synchronization
and multi-family/qualifier loops likewise retain and propagate returned datastores rather than
dropping proposal or inventory updates.

## Reconciliation

JD and CLD are not one transaction. If an apply fails after a JD mutation, the normal pipeline may
discard that run's datastore artifact. Retrying the operation or running proposal/node sync repairs
the projection without re-deriving node identity from jobs.
