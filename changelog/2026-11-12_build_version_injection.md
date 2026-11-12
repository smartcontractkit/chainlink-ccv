# Inject build identity (release tag and commit) into service binaries

## Executive Summary

Service images carry no build identity today, so nothing can report which release a running binary came
from. This change adds a `common/static` package holding `Version` and `Sha`, a `tools/bin/build-args`
script that derives them from git, and `--build-arg` plumbing through the five service Dockerfiles and the
`just` recipes that build them.

`Version` is a release tag only when the built commit is exactly that tag and no tracked file is modified;
otherwise it is the `unset` sentinel. `Sha` is always the full commit. Non-release builds stay honest
instead of reporting the last released version.

Affects the aggregator, verifier (committee and token), executor, indexer and pricer images. No runtime
behavior changes; nothing reads these values yet.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `static.Version`, `static.Sha`, `static.Unset` | added | `static\.(Version\|Sha\|Unset)\b` | `common/static/static.go:8` | [#new-package-commonstatic](#new-package-commonstatic) |
| `tools/bin/build-args` | added | `build-args` | `tools/bin/build-args:1` | [#build-arg-derivation](#build-arg-derivation) |
| `VERSION`, `COMMIT_SHA` build args | added | `build-arg VERSION` | `*/Dockerfile` | [#dockerfiles](#dockerfiles) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### New package `common/static`

- `static.Version` — the release tag the binary was built from, or `static.Unset`.
- `static.Sha` — the full commit the binary was built from, or `static.Unset`.
- `static.Unset` — the sentinel `"unset"`, for builds with no injected identity.

Both variables are set at link time with `-X github.com/smartcontractkit/chainlink-ccv/common/static.Version=…`
and `…/common/static.Sha=…`. A plain `go build` and every `go test` leave both `unset`.

### Build-arg derivation

`tools/bin/build-args` prints the flags callers pass to `docker build`:

```
$ ./tools/bin/build-args
--build-arg VERSION=0.18.0 --build-arg COMMIT_SHA=2ce98a8f934e857554e59de35971da45b20d22c7
```

- `VERSION` comes from `git describe --tags --exact-match --match 'v[0-9]*.[0-9]*.[0-9]*'` with the leading
  `v` stripped, so it matches the `vX.Y.Z` root release tag.
- `VERSION` is `unset` when `HEAD` is not exactly a root release tag, when any tracked file is modified, or
  when git metadata is unavailable. Module tags (`deployment/vX.Y.Z`, `verifier/v0.0.4-rc`) are ignored.
- `COMMIT_SHA` is always `git rev-parse HEAD`, or `unset` without git metadata.

Git is read on the host, not inside the image: `.dockerignore` excludes `.git`.

`--kv` prints the same values as `KEY=VALUE` lines, the format `docker/build-push-action`
takes, for callers that go through a reusable workflow instead of `docker build`. `--repo <path>`
describes another checkout, such as a worktree of an older ref:

### Dockerfiles

`aggregator`, `verifier`, `executor`, `indexer` and `pricer` take `ARG VERSION=unset` and
`ARG COMMIT_SHA=unset` and pass them to the linker. Both default to `unset`, so a caller that passes
nothing still produces a build that reports `unset` rather than failing.

The `just` recipes that own each image now derive the args themselves:

```just
build:
    docker build `../tools/bin/build-args` -f Dockerfile -t aggregator:latest ..
```

Same for `build-rc`, `build/devenv`'s `build-images-at`, and the GCP Marketplace job in
`.github/workflows/release-publish.yaml`. `build-images-at` passes `--repo <worktree>` so it describes the
ref it is about to build, and calls the current checkout's script because the older ref has no
`tools/bin/build-args` of its own.

Public ECR release images go through the reusable `reusable-docker-build-publish.yml` workflow, which
forwards its input verbatim to `docker/build-push-action`'s `build-args` (`KEY=VALUE` lines, not
`--build-arg` flags). `release-publish.yaml` therefore derives `VERSION`/`COMMIT_SHA` in a
`compute-build-identity` job and appends them to `docker-build-args`.

## Migration Guide

Downstream callers that build these images directly with `docker build` keep working: the build args
default to `unset`. To report a real version, pass them:

```sh
docker build $(./tools/bin/build-args) -f aggregator/Dockerfile -t aggregator:latest .
```

## Compatibility & Requirements

- Reading `VERSION` requires the tag to be present in the clone. `actions/checkout` needs
  `fetch-depth: 0`; every workflow that builds a release image sets it.
- The `.dev` images build through `air` and do not receive the args, so hot-reload builds report `unset`.
