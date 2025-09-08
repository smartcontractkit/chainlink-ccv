<div align="center">

# CCV Developer Environment

</div>

- [Components](#components)
- [Install and Run](#install)
- [Rebuilding Local Chainlink Node](#rebuilding-local-chainlink-node-image)
- [Testnets](#run-the-environment-testnets)
- [Creating components](#creating-components)
- [Tests](#smoke-e2e-test)


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
All build command are run using [Justfile](https://github.com/casey/just?tab=readme-ov-file#cross-platform), start with installing it
```
brew install just # click the link above if you are not on OS X
just clean-docker-dev # needed in case you have old JD image
just build-docker-dev
just cli
```

Enter `ccv` shell and follow auto-completion hints
```
ccv sh
```

## Rebuilding Local Chainlink Node Image
You can build a local image of CL node, please specify your `chainlink` repository path in `docker_ctx`
```
up env.toml,env-local-cl.toml
```

## Run the environment (testnets)
Test key address is `0xE1395cc1ECc9f7B0B19FeECE841E3eC6805186A5`, the private key can be found in 1Password `Eng Shared Vault -> CCIPv1.7 Test Environments`

Create `.envrc` and put the key there `export PRIVATE_KEY="..."` and select the network config
```
up env.toml,env-fuji-fantom.toml
```

### Developing the environment
We are using [Justfile](https://github.com/casey/just) for devs task
```bash
just fmt && just lint
```

### Creating Components
See the [guide](services/README.md)

### Running tests
Devenv include 2 types of tests: end-to-end system-level tests and services tests

#### Service Tests
Go to `tests/services` directory and run
```bash
go test -v -run TestService
```

#### Smoke E2E Test
Go to `tests/e2e` directory and run
```bash
go test -v -run TestE2ESmoke
```

#### Load/Chaos Tests
Spin up the observability stack first
```bash
export LOKI_URL=http://localhost:3030/loki/api/v1/push
ccv obs u
```

Go to `tests/e2e` directory and run

Clean load test
```bash
go test -v -run TestE2ELoad/clean
```

RPC latency test
```bash
go test -v -run TestE2ELoad/rpc_latency
```

Gas spikes
```bash
go test -v -run TestE2ELoad/gas
```

Reorgs (you need an env with Geth configured, `up env.toml,env-geth.toml`)
```bash
go test -v -run TestE2ELoad/reorgs
```

Services chaos
```bash
go test -v -run TestE2ELoad/services_chaos
```
