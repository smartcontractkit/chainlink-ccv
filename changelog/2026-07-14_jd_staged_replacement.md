# Staged JD job replacement

## Summary

JD-connected services can now prepare a replacement job before stopping the active job. The
bootstrap runner parses the incoming spec and constructs its chain registry while the current job
continues serving. Cutover remains single-active: the old service is stopped before the prepared
service is started.

This reduces replacement downtime without running two verifier or executor services at once.

## Behavior

The lifecycle manager recognizes an optional extension to `lifecycle.JobRunner`:

```go
type StagedJobRunner interface {
    JobRunner
    PrepareJob(ctx context.Context, spec string) error
    DiscardPreparedJob(ctx context.Context) error
}
```

For staged runners, replacement order is:

1. Persist the incoming proposal as pending.
2. Prepare the new job while the old job remains active.
3. Stop the old job.
4. Start the prepared job.
5. Promote and approve the proposal.

If preparation fails, the old job is left running and the prepared resources are discarded. If
activation fails after cutover, the existing old-job restart fallback still applies. Runners that
implement only `JobRunner` keep the existing stop-then-start behavior.

## Resource cleanup

Prepared registries can own RPC clients and head trackers before activation. Registry decorators
now forward optional `io.Closer` cleanup, and the EVM accessor factory closes its constructor-owned
resources exactly once. This cleanup also covers discarded candidates and partial construction
failures.

## Compatibility

- `JobRunner`, `Registry`, and `AccessorFactory` keep their existing required method sets.
- Custom runners and chain-family factories require no changes; staged preparation and terminal
  factory cleanup are opt-in.
- Solana and Canton continue using the existing bootstrap entry point and require no source or
  configuration migration.
- During preparation, EVM deployments may briefly hold both the active and candidate RPC
  connections. Operators should allow for that short overlap.

No application config or `blockchain_infos` APIs change in this release.
