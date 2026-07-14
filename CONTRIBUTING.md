# Contributing

Please read this before opening a PR. It exists so reviewers don't have to explain the same
things repeatedly.

## Pull request titles & commit messages

This repository follows the [Conventional Commits](https://www.conventionalcommits.org/)
specification, and **it is enforced** — a CI check ("Lint PR title (Conventional Commits)")
blocks merge until the PR title conforms.

PRs are merged via **squash**, and the repo is configured so the **PR title becomes the squash
commit subject**. That subject is what [Release Please](https://github.com/googleapis/release-please)
parses to compute version bumps and generate changelogs.
So the **PR title format is not optional**: a non-conforming title is invisible to Release Please —
no version bump, no changelog entry.

### Format

```
<type>(<scope>): <subject>
```

The `<type>` is mandatory; `<scope>` is optional.

### Type

Must be one of the following (these match the [`changelog-sections`](release-please-config.json)
Release Please uses). The "release impact" column reflects **current `0.x` behaviour** — every
managed module is pre-`1.0`, and the config sets `bump-minor-pre-major: true`, so breaking changes
bump the **minor** version rather than jumping to `1.0.0`:

| Type | When to use | Release impact (while `0.x`) |
|------|-------------|------------------------------|
| `feat` | A new feature | minor bump (`0.y.0`) |
| `fix` | A bug fix | patch bump (`0.0.z`) |
| `perf` | A performance improvement | patch bump |
| `revert` | Reverts a previous commit | patch bump |
| `build` | Build system or external dependencies | none |
| `chore` | Maintenance (dependency bumps, housekeeping) | none |
| `ci` | CI configuration or scripts | none |
| `docs` | Documentation only | none |
| `refactor` | Neither fixes a bug nor adds a feature | none |
| `style` | Formatting/whitespace — no behaviour change | none |
| `test` | Adding or correcting tests | none |

**Breaking changes:** append `!` after the type (e.g. `feat!:`) and/or add a `BREAKING CHANGE:`
footer. There is no separate "breaking" type. While a module is `0.x` this produces a **minor**
bump and is highlighted in the changelog; once a module reaches `1.0.0`, a breaking change will
bump the **major** version.

### Scope

The scope should identify the affected component (service, module, or tool):

```
feat(committeeverifier): add finality config product
fix(bootstrap): handle JD reconnect during key sync
```

Scope is optional and **advisory only** — Release Please routes a change to a module by the
**file paths it touches**, not by the scope string. Omit the scope when a change genuinely cuts
across components.

### Subject

- Imperative present tense: `add`, `fix`, `change` — not `added`, `fixes`, `changing`.
- Do not capitalise the first letter; no full stop at the end.

## Managed modules

Release Please independently versions and tags these Go modules:

| Module | Tag format |
|--------|------------|
| `.` (root) | `vX.Y.Z` |
| `deployment` | `deployment/vX.Y.Z` |
| `build/devenv` | `build/devenv/vX.Y.Z` |
| `integration/evm` | `integration/evm/vX.Y.Z` |

A single PR that touches more than one of these will bump each affected module independently.
Docker service images (`aggregator`, `verifier`, `executor`, `indexer`, `pricer`) are **not**
managed by Release Please — they continue to use the RC-tag flow.

## Detailed changelogs

For anything non-trivial (especially breaking changes), add a detailed entry under
[`changelog/`](changelog/) following [`changelog/.claude_template`](changelog/.claude_template).
This is separate from — and richer than — the auto-generated per-module `CHANGELOG.md` files.

## Before requesting review

- `just lint fix` — no new lint errors
- `just generate` — mocks and protobufs are up to date
- Detailed changelog added under `changelog/` if the change is breaking or notable
