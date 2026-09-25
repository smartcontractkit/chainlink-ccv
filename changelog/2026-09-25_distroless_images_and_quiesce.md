# Distroless production images and `ccv quiesce`

## Executive Summary

- All production images (aggregator, executor, indexer, pricer, verifier, devenv fakes) build their final stages from digest-pinned bases and run `gcr.io/distroless/static-debian12:nonroot` as user `65532:65532`: no shell, no package manager, no `apk upgrade` surface, and no per-service user accounts.
- The verifier image keeps tini as PID 1 (statically linked, copied from the builder) so the service is a child process; namespace init ignores SIGSTOP, so quiescing the verifier requires signaling the child.
- New `ccv quiesce pause|resume` CLI replaces `pkill -STOP/-CONT -f verifier`: the final images have no shell and therefore no pkill. The command finds the verifier service by scanning `/proc` for the lowest non-self PID whose `comm` matches the CLI binary's own name, then sends SIGSTOP/SIGCONT.
- New `.dockerignore` keeps VCS dirs, docs, changelogs, local keystores, and `build/devenv/*` (except the fakes module) out of every build context; new `.github/dependabot.yml` keeps the pinned digests current with one grouped weekly PR.
- Breaking for anything that exec-ed a shell in the images, matched the per-service users, or probed them with `kubectl exec ... wget` — see [Breaking Changes](#breaking-changes).

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `verifiercli.Client.Pause` | behavior-changed | `\.Pause\(` | `build/devenv/tests/e2e/verifiercli/client.go:109` | [#pause--resume-via-quiesce](#pause--resume-via-quiesce) |
| `verifiercli.Client.Resume` | behavior-changed | `\.Resume\(` | `build/devenv/tests/e2e/verifiercli/client.go:118` | [#pause--resume-via-quiesce](#pause--resume-via-quiesce) |
| `verifiercli.WithProcessMatch` | removed | `WithProcessMatch` | — | [#pause--resume-via-quiesce](#pause--resume-via-quiesce) |
| `verifiercli.DefaultProcessMatch` | removed | `DefaultProcessMatch` | — | [#pause--resume-via-quiesce](#pause--resume-via-quiesce) |
| `quiesce.InitQuiesceCommands` | added | `InitQuiesceCommands` | `cli/quiesce/quiesce.go:21` | [#quiesce-commands](#quiesce-commands) |
| `quiesce.findServicePID` | added | `findServicePID` | `cli/quiesce/quiesce.go:63` | [#quiesce-commands](#quiesce-commands) |
| `ccv quiesce pause` / `ccv quiesce resume` | added | `quiesce (pause|resume)` | `cmd/verifier/run_ccv_cli.go:117` | [#quiesce-commands](#quiesce-commands) |
| production Dockerfile final stages | behavior-changed | `distroless/static-debian12` | `verifier/Dockerfile` and siblings | [#distroless-final-stages](#distroless-final-stages) |
| image run users | behavior-changed | `USER 65532:65532` | same | [#distroless-final-stages](#distroless-final-stages) |
| build contexts | behavior-changed | `^build/devenv/\*` | `.dockerignore` | [#dockerignore](#dockerignore) |

## Breaking Changes

### Distroless final stages, no shell, nonroot user

- **What changed:** every production Dockerfile's final stage is `gcr.io/distroless/static-debian12:nonroot` (digest-pinned) instead of `alpine:3.23` with a per-service `adduser`; all images run as `USER 65532:65532`.
- **Before:** final images had busybox, `apk`, and users `aggregator:aggregator`, `executor:executor`, `indexer:indexer`, `pricer:pricer`, `verifier:verifier`, `fakes:fakes`; deployment docs used `kubectl exec ... -- wget` probes and `pkill` from inside the container.
- **After:** no shell, no `wget`, no `pkill`, no package manager. Runtime users are all `65532:65532`. The `verifier` ENTRYPOINT stays `["/sbin/tini", "--", "/bin/verifier"]` with statically linked tini copied from the builder; the `aggregator` stages its `/app/migrations` symlink in the builder (final image has no shell to create it).
- **Why:** smaller attack surface and immutable, supply-chain-verifiable bases; the distroless base also ships the CA certificates the services need.
- **Who is affected:** runbooks, k8s manifests, and CI that exec into these containers, reference the old users, or rely on a shell.

## Migration Guide

1. Replace in-container probes with a port-forward (the final images have no `wget`):

   ```sh
   # Before
   kubectl --context $CTX -n $NS exec deploy/$VER -- wget -qO- http://localhost:9988/health
   # After
   kubectl --context $CTX -n $NS port-forward deploy/$VER 9988:9988 & PF=$!
   sleep 2; curl -s http://localhost:9988/health; kill $PF
   ```

2. Replace pause/resume of the verifier service with the CLI (the images have no `pkill`):

   ```sh
   # Before
   kubectl --context $CTX -n $NS exec deploy/$VER -- pkill -STOP -f verifier
   # After
   kubectl --context $CTX -n $NS exec deploy/$VER -- /bin/verifier ccv quiesce pause
   ```

3. Update any user or volume ownership references from the per-service users to `65532` (the distroless nonroot UID).

4. Builders digest-pin `golang:1.26.6-alpine`/`golang:1.26.6`; bump digests only through the grouped weekly dependabot PR.

## New Features / Additions

- **`ccv quiesce pause|resume`** (`cli/quiesce`) — SIGSTOP/SIGCONT the verifier service in the same container, for curse replay and CLI mutations that must not race the running service. See [#quiesce-commands](#quiesce-commands).
- **Dependabot for base images** (`.github/dependabot.yml`) — weekly docker updates for all six production Dockerfiles, grouped into a single PR.
- **`.dockerignore`** — VCS dirs, `docs/`, `changelog/`, local keystores, `.env*` files, and `build/devenv/*` (except the fakes module, which the fakes image builds) never enter a build context.

## Validation

- `cli/quiesce` unit tests: lowest-PID selection, self-exclusion, no-match error, and a kill seam asserting the target PID and signal.
- The repo e2e suite (chain-status, policy hook, job queue, replay, reorg, chaos) drives `verifiercli.Pause`/`Resume` through `ccv quiesce` against the distroless verifier image — all green on the PR CI matrix.
- The devenv fakes image builds end-to-end from the new Dockerfile, `.dockerignore`, and pinned digests (verifies the `!build/devenv/fakes` negation keeps the module files in context).

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1474
- Updated runbook: `docs/migration/staging-migration-plan.md`
