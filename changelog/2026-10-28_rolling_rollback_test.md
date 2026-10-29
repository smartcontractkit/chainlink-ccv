# Add a rolling rollback e2e test

## Executive Summary

- Adds `TestE2ERollback_HappyPath`. It starts devenv on the images to upgrade to, then rolls back each service to the images to upgrade from, one at a time.
- A message must execute after each rollback, so the old images must run on the schema and data of the new images, for example after a DB migration.
- The `E2E Upgrade Test` workflow runs the rollback test in a separate job, under the same conditions as the upgrade test.
- Adds the PR label `upgrade-breaking-change`, which skips both jobs.
- Test and CI change only. No runtime behavior changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `services.RollbackContainer`, `services.ReplaceContainer` | added | `services\.(Rollback\|Replace)Container` | `build/devenv/services/upgrade.go` | [#container-swap](#container-swap) |
| `TestE2ERollback_HappyPath` | added | `TestE2ERollback_HappyPath` | `build/devenv/tests/e2e/upgrade_rolling_test.go` | [#test](#test) |
| `just rollback-test` | added | `rollback-test` | `build/devenv/Justfile` | [#run-locally](#run-locally) |
| `E2E Upgrade Test` matrix and skip label | changed | `upgrade-breaking-change` | `.github/workflows/test-upgrade.yaml` | [#ci](#ci) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Container swap

- `services.ReplaceContainer` has the swap logic. It keeps the old container as `<name><backupSuffix>`.
- `UpgradeContainer` uses the suffix `-pre-upgrade`. The new `RollbackContainer` uses `-pre-rollback`.
- Before this change, a second swap of the same container failed, because the `-pre-upgrade` name was already in use.

### Test

- `TestE2ERollback_HappyPath` checks that each container runs the `CCV_UPGRADE_IMAGE_TAG` image.
- It sends a message, then rolls back in reverse rollout order: executor, token-verifier, verifier, aggregator, indexer.
- The target of each rollback is the `CCV_UPGRADE_FROM_IMAGE_TAG` image. The test stops at the first failed rollback.

### Run locally

```bash
cd build/devenv
just rollback-test <from-commit> [to-commit]
```

The recipe builds the service images of both commits and starts devenv on the `to` images. It builds from git worktrees, so only committed changes are in the images.

### CI

- The `E2E Upgrade Test` job is now a matrix with two jobs: `TestE2EUpgrade_HappyPath` and `TestE2ERollback_HappyPath`. Each job has its own devenv.
- The PR label `upgrade-breaking-change` skips both jobs. Use it only for an intended break that a reviewer approves. Tag runs and manual runs ignore the label.
