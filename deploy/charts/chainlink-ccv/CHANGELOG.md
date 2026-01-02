# Changelog

This file documents all notable changes to the chainlink-cluster helm chart. The release numbering uses [semantic versioning](https://semver.org/).

> Note: this is a new changelog starting on v2.0.0. This consolidates all node deployments to a single chart and removes the need for the umbrella chart structure.

## 2.12.2

- Bump OTEL sidecar gRPC receiver `max_recv_msg_size_mib` from 8Mib set to 16 MiB

## 2.12.1

- Add `configOverrides` for OTEL sidecar telemetry and pipeline debug exporter settings
- Allows configuration of telemetry log level and encoding via `configOverrides.service.telemetry.logs.level` and `configOverrides.service.telemetry.logs.encoding`
- Allows enabling debug exporters per pipeline via `configOverrides.service.pipelines.{logs,metrics,traces}.exporters.debug`

## 2.11.1

- Lower otel processor default memory_limiter to `limit_mib: 256` and `spike_limit_mib: 64`

## 2.10.7

- Add `LogLevel` configuration option to OTEL sidecar for setting log level for telemetry (default: `''`)

## 2.10.4

- Increase OTEL sidecar memory limits to 1024Mi and 256Mi (default: 120Mi and 30Mi)

## 2.10.3

- Add `LogStreamingEnabled` configuration option to OTEL sidecar for enabling log streaming functionality (default: `false`)

## 2.9.9

- Add `config_version` resource attribute in the OTEL sidecar to support rollout/config diff correlation.

## 2.9.7

- Added configurable `max_recv_msg_size_mib` for OTEL sidecar gRPC receiver to handle larger message sizes (default: 4 MiB, configured: 8 MiB)

## 2.8.0

- Upgrade gateway egress network policy to allow access to rpc-proxy-2 namespace.

## 2.7.4

- configurable resource limit and request for otel sidecar

## 2.7.0

- Added customizable network policies for CRIB

## 2.3.3

- removed init-secrets-check init container

## 2.3.2

- regex hackery for scrapeconfig to be able to scrape metrics from service discovery endpoint

## 2.3.1

- add `common.chainlink.extraConfig` to allow mounting extra files on the node container

## 2.3.0

- add a default topology spread policy for best-effort distribution across multiple availability zones

## 2.2.0

- add ability to perform incremental rollout defined in sync phases

## 2.1.6

- add value rollout.progressDeadlineSeconds

## 2.1.5

- update init containers to reference index (manifest list) instead of amd64 manifest

## 2.1.0

- add global switch for all chart resources except for service account

## 2.0.2

- add tls switch for provisioner override

## 2.0.1

- remove `size` param and `boot` object
- replaced with `nodeCount`, `bootNodeCount`, `bootNodeSuffix`
- total `clusterSize` = `nodeCount` + `bootNodeCount`

## 2.0.0

- enable local development / decoupling from chainlink provisioner v1
- update templates to reduce merging complexity / move to helpers
- standardize labeling
- add example configurations applicable to all our use cases
- add testing w/ `helm unittest` (snapshot only)
- generate documentation w/ `helm-doc
- vpn node support
- scrapeconfig support
- gateway support
- oraclestore support
