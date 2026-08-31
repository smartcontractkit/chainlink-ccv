<div align="center">

# CCV Developer Environment

</div>

- [Components](#components)
- [Install](#install)
- [Running Tests](#running-tests)
- [Testnets](#run-the-environment-testnets)
- [Creating components](#creating-components)

## Components

- x2 Anvil chains
- NodeSet (4 nodes)
- Job Distributor
- [Fake Server](./fakes/README.md)
- [Indexer](../../indexer/README.md)
- [Aggregator](../../aggregator/README.md)
- [Verifier](../../verifier/README.md)
- [Executor](../../executor/README.md)

## Install

All build commands use [just](https://github.com/casey/just).

```bash
cd build/devenv
just build-docker-dev   # build all service images
just cli                # install the ccv CLI binary
```

> **Production images**: By default the env runs production images (`:latest`). To hot-reload a specific service, change its tag to `:dev` in `env.toml` and run `just build-docker-dev`.

## Running Tests

`ccv test` handles image build, env startup, and test execution in one command. Run from `build/devenv`.

### Quick start

```bash
# Full cycle — build images, start env, run test, log to file:
ccv test --profile standard.profile --pattern TestE2ESmoke_Basic --log /tmp/test.log

# With Chainlink nodes:
ccv test --profile standard.clnode.profile --pattern TestE2ESmoke_Basic --log /tmp/test.log

# Named suite aliases (smoke, load, chaos, etc.):
ccv test smoke --profile standard.profile --log /tmp/test.log

# Skip rebuild if images are already current:
ccv test smoke --profile standard.profile --build=false --log /tmp/test.log
```

The `--log <path>` flag redirects all verbose output (docker build, env startup, go test) to a file so only progress lines appear on the terminal.

### Profiles

A `.profile` file encodes the full environment configuration — mode, config files, and output path. Built-in profiles in `build/devenv/`:

| Profile | Use |
|---------|-----|
| `standard.profile` | Default standalone env |
| `phased.profile` | Phased runtime standalone |
| `standard.clnode.profile` | Standalone + local Chainlink nodes |
| `standard.src-auto-mine.profile` | Standalone + auto-mine source chain |
| `standard.one-exec-per-chain.profile` | Standalone + one executor per chain |
| `standard.ha.clnode.profile` | High-availability + Chainlink nodes |
| `phased.clnode.profile` | Phased runtime + Chainlink nodes |
| `standard.rpc-failover.profile` | Standalone + RPC failover proxies |
| `phased.rpc-failover.profile` | Phased runtime + RPC failover proxies |

> **CI profiles** (`*.ci.profile`) reference CI-specific image tags and paths. Do not use them locally.

### Local networks

The `[local_networks]` section layers chain-family-owned extensions on top of the
blockchains devenv launches. Today the only extension is RPC failover: a primary
and a secondary reverse proxy in front of each chain's RPC endpoint. Standalone
services see only the proxies and the secondary starts stopped, so a chaos test
can stop the endpoint the services are using and watch the multi-node client move
to the other one. Test-side clients keep the direct endpoint at index 0 of the
blockchain output, which no proxy outage can take away.

Enable it per family:

```toml
[local_networks]
version = 1

[local_networks.evm.input.rpc_failover]
enabled = true
```

The orchestration in `localnetwork/` is family-agnostic — it derives the proxy
listeners from the chain's own node URLs, so a family that serves RPC and
WebSocket on separate ports (Solana: 8899/8900) gets one listener per port. A
family opts in by registering the shared configurator, in this repo or in a
product repo that imports it:

```go
chainreg.Register(chainsel.FamilySolana, chainreg.Registration{
    LocalNetworkConfigurator: localnetwork.Configurator(chainsel.FamilySolana),
})
```

Tests drive the proxies through `tests/e2e/tcapi/chaos`, which resolves the
container names from the environment output by chain selector:

```go
proxies, err := chaos.RPCFailoverChainFor(cfg, selector)
err = chaos.SetRPCProxyRunning(ctx, proxies.PrimaryContainerName, false)
t.Cleanup(func() { chaos.RestoreRPCProxies(ctx, proxies) })
```

### `ccv test` flags

| Flag | Default | Notes |
|------|---------|-------|
| `--profile` / `-p` | — | Profile to start; writes per-run output file |
| `--pattern` / `-r` | — | Raw Go `-run` pattern; mutually exclusive with suite name |
| `--build` | `true` | Build Docker images; pass `--build=false` to skip |
| `--timeout` | unlimited | Passed to `go test -timeout` |
| `--log <path>` | — | Write all output to file; terminal shows only progress |

### Manual steps (env already running)

Start the environment separately:

```bash
ccv up --profile standard.profile
ccv up --profile standard.clnode.profile   # with Chainlink nodes
ccv down                                    # tear down
```

Then run tests directly:

```bash
cd tests/e2e
go test -v -timeout 15m -count=1 -run TestE2ESmoke_Basic
```

#### Pointing tests at the right env (`SMOKE_TEST_CONFIG`)

The smoke tests read the running environment from a config file. The path defaults
to `../../env-out.toml` and is overridden by the `SMOKE_TEST_CONFIG` environment
variable. Set it to the output file written by the `ccv up` you ran.

The output filename is derived from the base config file by inserting `-out` before
`.toml` (unless overridden with `ccv up --output <path>`):

| Startup command | Output file | `SMOKE_TEST_CONFIG` |
|-----------------|-------------|---------------------|
| `ccv up env.toml` / `ccv up --profile standard.profile` | `env-out.toml` | unset (default) |
| `ccv up --env-mode phased env-phased.toml` / `ccv up --profile phased.profile` | `env-phased-out.toml` | `../../env-phased-out.toml` |
| `ccv up --output <path> …` | `<path>` | `../../<path>` (or an absolute path) |

So to run the smoke suite against a phased environment:

```bash
cd tests/e2e
SMOKE_TEST_CONFIG=../../env-phased-out.toml go test -v -timeout 15m -count=1 -run TestE2ESmoke_Basic
```

> `ccv test` sets this automatically from the profile's per-run output file, so you
> only need `SMOKE_TEST_CONFIG` when running `go test` by hand against a manually
> started env.

### Interactive shell

```bash
ccv shell --profile standard.profile   # starts shell with auto-completion
ccv sh                                  # uses standard.profile by default
```

### Load and chaos tests

Start the observability stack first, then use `ccv test`:

```bash
ccv obs up -m loki
ccv test load --profile standard.profile --log /tmp/load.log
ccv test chaos --profile standard.profile --log /tmp/chaos.log
```

Or run directly:
```bash
export LOKI_URL=http://localhost:3030/loki/api/v1/push
cd tests/e2e
go test -v -run TestE2ELoad/clean
go test -v -run TestE2ELoad/rpc_latency
go test -v -run TestE2ELoad/gas
```

## Rebuilding Local Chainlink Node Image

Checkout the `chainlink` repository (sibling of `chainlink-ccv`) and update the `chainlink-ccv` version:

```bash
# In the chainlink repo
go get github.com/smartcontractkit/chainlink-ccv@latest && make gomodtidy
```

Then run with the CL node profile — Docker will rebuild automatically:

```bash
ccv test --profile standard.clnode.profile --pattern TestE2ESmoke_Basic --log /tmp/test.log
```

## Run the environment (testnets)

Test key address is `0xE1395cc1ECc9f7B0B19FeECE841E3eC6805186A5`, private key in 1Password `Eng Shared Vault -> CCIPv1.7 Test Environments`.

Create `.envrc`:
```bash
export PRIVATE_KEY="..."
```

Then start with a testnet config:
```bash
ccv up env.toml,env-fuji-fantom.toml
```

## Testing with AWS KMS (keystore backend)

By default services use the Postgres keystore. To exercise the AWS KMS backend, set it in the
service's bootstrap keystore config in your env file (pre-provision the KMS keys out of band):

```toml
[verifier.bootstrap.keystore]
backend = "kms"
[verifier.bootstrap.keystore.kms]
region         = "us-west-2"
ecdsa_key_id   = "arn:aws:kms:us-west-2:<acct>:key/<id>"   # secp256k1
ed25519_key_id = "arn:aws:kms:us-west-2:<acct>:key/<id>"   # Ed25519 CSA key
```

The container reaches KMS via the AWS default credential chain, so export credentials into the shell
that runs `ccv up` first — devenv forwards `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` / `AWS_REGION` into the container, but **only** for KMS-backed services
(see `ForwardedAWSEnv` in `services/common.go`):

```bash
aws sso login --profile <p>
eval "$(aws configure export-credentials --profile <p> --format env)"
export AWS_REGION=us-west-2
ccv up env.toml
```

The IAM principal needs `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on those key ARNs. This
credential forwarding is a local-dev convenience only; production uses IRSA / instance roles. Verify
via the bootstrap info server (`POST /keystore/reader/getkeys`) — the returned public keys should
match `aws kms get-public-key` for the ARNs.

## Running without a Job Distributor (`app_config_source = "local"`)

By default the environment starts a Job Distributor and ships each service's app config via job
proposals. Set the top-level `app_config_source = "local"` in the env file to run **without** JD — for
example when the `job-distributor` image is not available (the CCV starter kit, partner testing).

```bash
ccv up env-local-config.toml
```

In local mode:

- No Job Distributor is started.
- Committee verifiers and executors run in bootstrap local mode: each boots serving its keys, and its
  app config is delivered as a mounted file after contracts are deployed (the bootstrapper waits for
  it).
- Verifier signer addresses are read from the bootstrap info server instead of JD, then used to
  configure the on-chain committee and the aggregator. Executor transmitters are funded from the same
  bootstrap keys.

This covers the full send -> verify -> execute flow without the JD image. `env-local-config.toml` is a
minimal single-committee, single-executor example to copy.

### Developing the environment

```bash
just fmt && just lint
```

### Creating Components

See the [guide](services/README.md).

### On-Chain Monitoring

Implement on-chain transformations in [CollectAndObserveEvents](monitoring.go) and expose metrics via `promauto`, then upload:

```bash
upload-on-chain-metrics
```

Go to [dashboards](dashboards) and render metrics. Default Loki stream: `{job="on-chain"}`.

## Docker Desktop on Linux

If the Docker socket is in a non-standard location, either symlink it:

```bash
sudo ln -s $HOME/.docker/run/docker.sock /var/run/docker.sock
```

Or export `DOCKER_HOST`:

```bash
export DOCKER_HOST unix://$HOME/.docker/desktop/docker.sock
```

## getDX tracking

getDX tracks environment startup success/failure rate, config files used, truncated error messages, and startup time.
