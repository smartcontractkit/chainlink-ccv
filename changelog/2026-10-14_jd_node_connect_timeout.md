# Configurable JD node connect timeout

## Summary

The wait for CL nodes, executors, and verifiers to connect to JD after
registration is now configurable via an optional `[jd] node_connect_timeout`
key in the devenv TOML, with a fallback default. It was previously hardcoded at
60 seconds, which large or emulated devenvs can exceed between container start
and the node's WSRPC dial landing. The default is now 3 minutes, and the wait
is a hard bound: each `GetNode` RPC runs under a context derived from the
remaining deadline, so a hung JD cannot block past it.

This change is backwards compatible: no TOML key is required, and no exported
function signature changed.

## Config

Optional key under `[jd]`, any Go duration string:

```toml
[jd]
  # node_connect_timeout = "5m"   # optional; default 3m
```

Unset, empty, or invalid values fall back to the 3-minute default (invalid
values log a warning). The setting is read by both environment runtimes:

| Path | How the value flows |
|------|---------------------|
| Legacy (monolith) `ccv up` | `[jd]` → `Cfg.JD.NodeConnectTimeout` → `jobs.StartJDInfrastructure` → `jobs.JDInfrastructure` |
| Phased runtime | `[jd]` → jd component → `jobs.StartJDInfrastructure` → `jobs.JDInfrastructure` |
| Migration cutover (`migration.Run`) | the `JDInfrastructure` handed in `migration.Input` |

All JD connection waits resolve the value through
`(*jobs.JDInfrastructure).ConnectTimeout()`, which is nil-safe and falls back
to the default when the field is empty.

## Hard bound on the RPC

`waitForConnection` (behind `WaitForNodeConnection` and
`WaitForBootstrapConnection`) polls every 2s. Each `GetNode` call now runs
under `context.WithTimeout(ctx, time.Until(deadline))`, so a hung or
unresponsive JD gRPC call is cancelled at the deadline instead of blocking the
wait indefinitely. Transient `GetNode` errors are still tolerated while the
deadline has not passed.

## Non-breaking API note

`committeeverifier.RegisterStandaloneVerifiersWithJD` keeps its existing
signature and behavior (it uses the default timeout):

```go
func RegisterStandaloneVerifiersWithJD(ctx context.Context, verifiers []*Input, jdClient offchain.Client) error
```

A new wrapper takes the JD infrastructure and honors the configured
`[jd] node_connect_timeout`:

```go
func RegisterStandaloneVerifiersWithJDFromInfra(ctx context.Context, verifiers []*Input, jdInfra *jobs.JDInfrastructure) error
```

Callers that want the configured timeout should migrate to the `FromInfra`
variant; the committeeccv devenv component already uses it.

## Behavioral note

The default wait went from 60s to 3m. The success path is unchanged (the wait
returns as soon as JD reports the node connected); a node that never connects
now fails after 3 minutes instead of 1. A one-time warning is logged once a
wait passes the 60-second mark so the longer wait stays visible at default
log level. The migration cutover waits previously used their own 90-second
constant; they now follow the same config and default.
