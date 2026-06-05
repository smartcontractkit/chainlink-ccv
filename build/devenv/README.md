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

> **CI profiles** (`*.ci.profile`) reference CI-specific image tags and paths. Do not use them locally.

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
