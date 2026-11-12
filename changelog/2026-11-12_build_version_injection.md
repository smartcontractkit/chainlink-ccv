# Inject build identity (version and commit) into service binaries

## Executive Summary

Service images carry no build identity today, so nothing can report which build a running binary came
from. This change adds a `common/static` package holding `Version` and `Sha`, a `tools/buildargs` command
that names the built commit, and `--build-arg` plumbing through the five service Dockerfiles and the
`just` recipes that build them.

`Version` is the root release tag when the built commit is exactly that tag, otherwise the commit's Go
pseudo-version (`v0.18.1-0.20261112144744-8add7e137610`), and `unset` when the tree is not a commit that
can be named: uncommitted changes, a shallow clone, or no git metadata. `Sha` is always the full commit.

Affects the aggregator, verifier (committee and token), executor, indexer and pricer images. No runtime
behavior changes; nothing reads these values yet.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `static.Version`, `static.Sha`, `static.Unset` | added | `static\.(Version\|Sha\|Unset)\b` | `common/static/static.go:8` | [#new-package-commonstatic](#new-package-commonstatic) |
| `main.derive` | added | `\bderive\(` | `tools/buildargs/main.go:60` | [#build-identity-derivation](#build-identity-derivation) |
| `VERSION`, `COMMIT_SHA` build args | added | `build-arg VERSION` | `*/Dockerfile` | [#dockerfiles](#dockerfiles) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### New package `common/static`

- `static.Version` — the release tag or Go pseudo-version of the built commit, or `static.Unset`.
- `static.Sha` — the full commit the binary was built from, or `static.Unset`.
- `static.Unset` — the sentinel `"unset"`, for a tree that is not a namable commit.

Both variables are set at link time with `-X github.com/smartcontractkit/chainlink-ccv/common/static.Version=…`
and `…/common/static.Sha=…`. A plain `go build` and every `go test` leave both `unset`.

### Build identity derivation

`go run ./tools/buildargs` prints the flags callers pass to `docker build`:

```
$ go run ./tools/buildargs
--build-arg VERSION=v0.18.1-0.20261112144744-8add7e137610 --build-arg COMMIT_SHA=8add7e137610b6acfc9522b50f687b1662d5b557
```

| tree state | `VERSION` |
|---|---|
| HEAD is exactly a root release tag | that tag, e.g. `v0.18.0` |
| HEAD after a root release tag | pseudo-version of HEAD, e.g. `v0.18.1-0.20261112144744-8add7e137610` |
| no reachable root release tag | `v0.0.0-<timestamp>-<rev>` |
| uncommitted tracked changes | `unset` |
| shallow clone | `unset`, with a warning on stderr |
| not a git checkout | `unset` |

- Pseudo-versions come from `golang.org/x/mod/module.PseudoVersion`, so the base bump, timestamp and
  12-character revision follow Go's rules rather than a local approximation.
- Only root tags matching `v[0-9]*.[0-9]*.[0-9]*` count. Module tags (`deployment/vX.Y.Z`,
  `verifier/v0.0.4-rc`) are ignored.
- A shallow clone is reported as `unset` rather than `v0.0.0-…`: without history or tags, a derived
  pseudo-version would sort below every release it actually follows. `COMMIT_SHA` still identifies the
  build, so this is not an error.
- A checkout with no git metadata is an **error**, not `unset`: the command exits 1, so the image is never
  built without identity. Nothing downstream could tell such an image from a correctly built one.
- Untracked files do not make a build `unset`, so local build output does not erase the version.

The `just` recipes run the command in a shell with `set -e` rather than a backtick substitution, so a
failure to run it at all — missing Go toolchain, a module path that does not resolve — fails the recipe
instead of silently substituting an empty string and building with the `unset` defaults. Recipe lines run
under `sh`, which is dash on Linux CI, so they stay POSIX (`set -eu`, no `pipefail`); the verifier recipe,
which builds two images, uses a bash shebang instead.

Git is read on the host, not inside the image: `.dockerignore` excludes `.git`.

`--kv` prints the same values as `KEY=VALUE` lines, the format `docker/build-push-action` takes, for
callers that go through a reusable workflow instead of `docker build`. `--repo <path>` describes another
checkout, such as a worktree of an older ref.

### Dockerfiles

`aggregator`, `verifier`, `executor`, `indexer` and `pricer` take `ARG VERSION=unset` and
`ARG COMMIT_SHA=unset` and pass them to the linker. Both default to `unset`, so a caller that passes
nothing still produces a build that reports `unset` rather than failing.

The `just` recipes that own each image derive the args themselves:

```just
build:
    @set -euo pipefail; args=$(go -C .. run ./tools/buildargs); docker build $args -f Dockerfile -t aggregator:latest ..
```

`go -C` is required because `build/devenv` is a separate module: it cannot `go run` a path outside itself.
Service Justfiles are one level below the root and use `-C ..`; `build/devenv` is two and uses `-C ../..`.
Same for `build-rc`, and for the GCP Marketplace job in `.github/workflows/release-publish.yaml`.
`build-images-at` passes `--repo <worktree>` so it describes the ref it is about to build, and runs the
current checkout's tool because the older ref has no `tools/buildargs` of its own.

Public ECR release images go through the reusable `reusable-docker-build-publish.yml` workflow, which
forwards its input verbatim to `docker/build-push-action`'s `build-args` (`KEY=VALUE` lines, not
`--build-arg` flags). `release-publish.yaml` therefore derives `VERSION`/`COMMIT_SHA` in a
`compute-build-identity` job and appends them to `docker-build-args`.

## Migration Guide

Downstream callers that build these images directly with `docker build` keep working: the build args
default to `unset`. To report a real version, pass them:

```sh
docker build $(go run ./tools/buildargs) -f aggregator/Dockerfile -t aggregator:latest .
```

## Compatibility & Requirements

- Building an image now needs a Go toolchain on the host, because the version is derived by a Go command
  rather than a shell script. Every workflow that builds images sets up Go from the root `go.mod`.
- Deriving a version requires the tag in the clone. `actions/checkout` needs `fetch-depth: 0`; every
  workflow that builds a release image sets it.
- The `.dev` images build through `air` and do not receive the args, so hot-reload builds report `unset`.
