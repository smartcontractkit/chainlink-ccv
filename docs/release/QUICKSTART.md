<!-- VERSION: 1.0.0 -->

# Release Setup QUICKSTART

**Document version: `1.0.0`** (semver — see [Versioning this document](#versioning-this-document))

This guide brings a chainlink-ccv-family Go repo onto our standard release process:
**automated per-module semantic versioning driven by Conventional Commits**, with
generated `CHANGELOG.md`s, `go get`-resolvable tags, and (optionally) GA Docker images
published on release. It is derived from the reference implementation in this repo.

Copy-paste sample files live in [`samples/`](samples/). Placeholders are marked
`REPLACE_ME...` (values) or `# EDIT:` (comments). Everything not so marked is the
standard and should be copied verbatim, including the pinned action SHAs.

---

## Contents

- [Principles](#principles)
- [Mental model: what release-please manages, and what merely reacts to it](#mental-model-what-release-please-manages-and-what-merely-reacts-to-it)
- [What you will add](#what-you-will-add)
- [Prerequisites (do these first, in order)](#prerequisites-do-these-first-in-order)
- [Adoption steps](#adoption-steps)
- [Patching a released version (hotfixes)](#patching-a-released-version-hotfixes)
- [Conventions (the standard, in one place)](#conventions)
- [Versioning this document](#versioning-this-document)
- [Changelog](#changelog)

---

## Principles

The setup below follows from a few beliefs. When a specific rule seems fussy, it usually
traces back to one of these — so they come first.

- **`main` is always shippable.** Every PR clears required checks and Conventional-Commit
  gating before it merges, and we release frequently, so the tip of `main` is a valid
  release at any moment. This is what lets us **roll forward** instead of maintaining
  release branches, and it reframes an unshippable commit as a bug in `main` to fix (revert
  it, gate it behind a flag) — never a reason to route around `main`.

- **Versioning is derived, not decided.** Authors declare the *intent* of a change
  (`feat` / `fix` / `!`); release-please computes the version, tag, and `CHANGELOG.md` from
  that intent. Nobody hand-picks a version number. This removes a class of human error and
  makes every release reproducible from history alone.

- **The PR title is the release record.** The repo is squash-merge-only, so the PR title
  becomes the squash subject — the single line release-please reads. That is why it is
  linted as a Conventional Commit and required from day one: a title that doesn't parse is
  dropped from the changelog silently and permanently.

- **Prefer the minimal, explicable standard; earn every mechanism.** We default to the
  boring option and add machinery only against a concrete, reproduced failure — never a
  hypothetical one. This is why the config carries no unexplained workarounds, why there is
  no codegen tool yet, and why hotfix branches are documented but not standing. A documented
  escape hatch beats speculative complexity.

- **One linear history, one source of truth.** Each version is an ancestor of the next, and
  "what's in prod" is a point on `main` rather than a reconciliation across branches.
  Anything that forks that narrative (a long-lived release branch) is a deliberate
  exception, not routine.

---

## Mental model: what release-please manages, and what merely reacts to it

This is the single most important distinction; get it wrong and the config misattributes
commits.

- **Managed Go modules** — the units release-please versions, tags, and generates a
  `CHANGELOG.md` for. A module is worth managing if it is **either** consumed downstream
  via `go get`, **or** builds an executable that ships as a Docker image (the module
  version becomes the image tag), **or** both — all of these warrant semantic versioning.
  Each managed unit is a `go.mod` (the root module is the repo root itself). **These are
  what the release-please config manages.**
- **Docker image publishing** — orthogonal downstream wiring, not something release-please
  versions. A release tag *triggers* a GA image build via the optional
  `release-publish.yaml`. The trigger shape depends on how the repo is laid out:
  - Services that live as *subdirectories inside the root module* (as in this repo, built
    via `just <svc>/build` + `publish`) have no `go.mod` of their own, so they are pinned
    to the **root** version and published when the root release tag is cut.
  - A repo where the releasable unit *is* its own module publishes its image off that
    module's own release tag.

A repo that publishes no images simply omits `release-publish.yaml`.

---

## What you will add

| File | Required? | Purpose |
| ---- | --------- | ------- |
| `release-please-config.json` | Yes | Declares managed modules + root `exclude-paths`. |
| `.release-please-manifest.json` | Yes | Current version of each managed module. |
| `.github/workflows/release-please.yaml` | Yes | Opens release PRs, cuts tags. |
| `.github/workflows/pr-checks.yaml` | Yes | Required Conventional-Commit PR-title lint. |
| `.github/workflows/release-publish.yaml` | Only if repo ships Docker services | Publishes GA images on a root release tag. |

---

## Prerequisites (do these first, in order)

1. **Releng: a write-scoped GATI role** (`contents:write` + `pull-requests:write`).
   Confirm the three secrets referenced by `release-please.yaml` exist in your repo:
   `GATI_AWS_ROLE_ARN_AUTO_PR_TOKEN_ISSUER`, `GATI_LAMBDA_URL_CCIP_PROTOCOL`,
   `GATI_AWS_REGION`. A read-only GATI role is **insufficient**.

2. **Repo settings: force the PR title to be the squash subject, with an empty body.**
   ```bash
   gh api -X PATCH repos/<org>/<repo> \
     -f squash_merge_commit_title=PR_TITLE \
     -f squash_merge_commit_message=BLANK
   ```
   `BLANK` is important: `COMMIT_MESSAGES` causes **duplicate changelog entries**,
   because release-please parses Conventional-Commit lines in the commit *body* as
   additional commits.
   Also enable "Allow GitHub Actions to create and approve pull requests" if needed.

3. **Anchor tags.** Each managed module needs a starting tag matching its manifest
   entry, or release-please has no baseline. If a module has no prior tag, create one:
   ```bash
   git tag <module-path>/v0.0.1 <baseline-sha>   # or bare v0.0.1 for the root module
   git push origin <module-path>/v0.0.1
   ```
   Deleting existing published version tags is harmful — leave them; release-please reads
   the manifest, not tags, to pick the next version.

4. **Branch protection:** add **Lint PR title (Conventional Commits)** as a required check.

---

## Adoption steps

1. **Inventory your releasable modules.** `find . -name go.mod -not -path '*/vendor/*'`.
   A module is *managed* if it has (or will have) downstream `go get` consumers **or**
   builds an executable shipped as a Docker image — either warrants semver. Test-support
   and codegen-only modules are typically excluded.

2. **Copy the samples** into the repo root / `.github/workflows/` and fill placeholders:

   - **`release-please-config.json`** — one `packages` entry per managed module.
     - The root `"."` entry gets **no** `package-name` (so its tags stay bare `vX.Y.Z`).
     - Every **other** managed module gets `"package-name": "<its-path>"`.
     - **Root `exclude-paths` is the critical knob.** Root's `"."` matches *every* file, so
       without excludes it claims every commit. Exclude: every other managed module path,
       every non-managed submodule path, and non-library noise (`changelog`, `docs`,
       `.github`, generated `tools/` dirs). Do **not** exclude root `go.mod`/`go.sum` — a
       root dependency bump is a real root change. Keep the list **tight**: an over-broad
       exclude makes release-please silently ignore wanted commits.
   - **`.release-please-manifest.json`** — one line per managed module, each at its current
     version (match your anchor tags; new modules start at `0.0.1`).
   - **`release-please.yaml`** — confirm the GATI secret names; otherwise verbatim.
   - **`pr-checks.yaml`** — verbatim.
   - **`release-publish.yaml`** — *only if you ship Docker services.* Fill the `module:`
     matrix and the ECR registry/role secret names. Otherwise delete this file.

3. **Sanity-check the first release PR.** Because pre-adoption history isn't
   Conventional-Commit formatted, no release fires until the next `feat:`/`fix:` lands.
   When it does, verify: (a) one release PR *per* managed module (`separate-pull-requests`),
   (b) the **root** PR produces a **bare `vX.Y.Z`** tag — if it prefixes, set `"component": ""`
   on the root package explicitly — and (c) each PR reflects the *right* commits for its
   module (a misattribution means an `exclude-paths` bug).

4. **Watch for wedged required checks.** Path-filtered required checks can sit "pending"
   on a release PR that doesn't touch their path, and `push`/`merge_group`-only checks
   won't run on the bot PR. Mark such checks not-strictly-required or add an always-runs
   gate job.

---

## Patching a released version (hotfixes)

**The standard is roll-forward: fix on `main`, let the normal release-please flow cut the
next version.** Suppose your latest release is `v0.10.0`. You merge a `fix:` PR to `main` 
like any other change, and release-please ships it as `v0.10.1` (or folds it into the next 
`v0.11.0` if features also landed). You do **not** maintain long-lived release branches by 
default.

### Why roll-forward, not a maintenance-branch backport

The alternative — the chainlink-node pattern of a `release/vX.Y.Z` branch you cherry-pick
fixes onto and cut patches from — exists to solve one specific problem: *shipping a minimal
fix without also shipping the commits that landed on `main` since the release.* That is only
worth its cost when those intervening commits are a liability you must exclude. Our default
assumes the opposite, for concrete reasons:

- **`main` is always shippable** (the first [principle](#principles)). The commits that
  landed since `v0.10.0` are themselves prod-bound on the next release — not an unvetted
  backlog you need to hold back. If a specific one *isn't* safe to ship, that is a signal to
  fix `main`'s shippability, not to route around it.
- **A branch is a second reality to maintain.** A release branch needs its own release-please
  invocation, its own manifest state, and a discipline of cherry-picking every fix onto both
  branches in the right order. That machinery drifts and rots when it's used rarely — and by
  design it *is* used rarely — so it's most likely to be broken exactly when an incident
  finally needs it.
- **Roll-forward keeps one source of truth.** History stays linear, each version is an
  ancestor of the next, and the changelog reads as one story. Backport branches fork the
  narrative: `v0.10.1` and `v0.11.0` can contain different fixes, and reconciling "what's
  actually in prod" becomes a cross-branch diff.
- **The escape hatch is cheap to add later, retroactively.** Because you can branch from an
  already-published tag at any time (see the sketch below), deferring costs nothing: the day a
  real incident demands a minimal patch, the branch is an afternoon of setup against a known
  commit — not a decision you had to pre-pay.

**When to reconsider:** if a client repo ships to an environment where taking `main`'s
divergence is genuinely unacceptable (strict change-control, a customer pinned to `v0.10.x`
demanding a security patch and nothing else), the backport flow below is fully supported.

### Sketch: a maintenance-branch hotfix with release-please

release-please supports this natively via `target-branch` — no new tooling, just a branch and
a scoped workflow. To patch a shipped `v0.10.0`:

1. **Fix `main` first.** Merge the `fix:` PR to `main` as normal. This keeps `main` correct and
   gives you a commit to backport (never patch only the branch — that reintroduces the bug on
   the next `main` release).
2. **Branch from the released tag:**
   ```bash
   git checkout -b release/0.10 v0.10.0
   git push origin release/0.10
   ```
   That branch's `.release-please-manifest.json` already reads `0.10.0` — the baseline
   release-please bumps from.
3. **Cherry-pick just the fix** onto the branch: `git cherry-pick <sha>`, push.
4. **Run release-please against the branch.** Add a workflow scoped to `release/**` that sets
   `target-branch` (the default workflow only manages `main`):
   ```yaml
   on:
     push:
       branches: [ 'release/**' ]
   # ...same steps as release-please.yaml, plus:
       with:
         target-branch: ${{ github.ref_name }}
         config-file: release-please-config.json
         manifest-file: .release-please-manifest.json
   ```
   release-please reads the branch's manifest (`0.10.0`), sees one `fix:`, opens a release PR
   **against the branch**, and on merge cuts **`v0.10.1`** — carrying only the cherry-pick,
   none of `main`'s divergence.
5. **Docker publish needs no changes.** Tags aren't branch-scoped, so the `v0.10.1` tag matches
   `release-publish.yaml`'s `v[0-9]+.[0-9]+.[0-9]+` glob and publishes an image built from the
   branch's state — same as a `main` release, and it fires because the tag is pushed under the
   GATI app token.

---

## Conventions

- **Manifest mode, `release-type: go`**, `separate-pull-requests: true`, `tag-separator: "/"`.
- **Stay on `0.x` deliberately:** `bump-minor-pre-major: true`. Going to `1.0.0` is a
  deliberate future act, not an accident.
- **Conventional Commits enforced on PR titles, required from day one.** `feat`/`fix`/`!`
  set the bump level; commit *scopes* are optional (routing is by changed-file path, not
  scope).
- **Changelog-only PRs** (touching only excluded paths like `changelog/`) intentionally
  trigger no release.
- **Hotfixes roll forward** — patch by fixing `main` and cutting the next version, not via
  maintenance branches (see [Patching a released version](#patching-a-released-version-hotfixes)).
- **Pinned action SHAs are part of the standard.** Bump them deliberately and bump this
  document's VERSION when you do.

---

## Versioning this document

The `<!-- VERSION: X.Y.Z -->` header at the top is the semantic version of *this process*,
independent of any repo's own version. Adopters cite it ("we're on release QUICKSTART
`1.0.0`") so drift between repos is a diffable fact.

- **patch** — clarifications, typo fixes, non-behavioral wording.
- **minor** — additive, backward-compatible changes (a new optional file/field/step) that
  don't force existing adopters to change anything.
- **major** — a change that requires adopters to modify what they've already stamped
  (a renamed field, a changed default, a retired file, a bumped required action SHA).

When you change the standard, bump the header and note it below.

## Changelog

- **1.0.0** — Initial standard, extracted from the chainlink-ccv reference implementation.
