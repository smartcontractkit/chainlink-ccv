# JD replacement validation

## Summary

JD-connected services now validate a replacement job before stopping the active job. Validation
parses the outer job spec and runs the application factory's config checks without starting
services or constructing chain registries.

This keeps the current verifier or executor available when a proposed application config is
invalid while preserving the existing stop-then-start lifecycle.

## Behavior

The lifecycle manager recognizes an optional extension to `lifecycle.JobRunner`:

```go
type ValidatingJobRunner interface {
    JobRunner
    ValidateJob(ctx context.Context, spec string) error
}
```

For validating runners, replacement order is:

1. Validate the new job while the old job remains active.
2. Persist the incoming proposal as pending.
3. Stop the old job.
4. Start the new job and construct its runtime resources.
5. Promote and approve the proposal.

If validation fails, the proposal is not persisted and the old job continues uninterrupted. If
stopping or starting after validation succeeds fails, the manager removes the pending proposal and
restarts the old spec. A failed old-job restart moves the manager to `WaitingForJob`. Health or
readiness failures that occur after `StartJob` succeeds do not currently trigger rollback.

## Compatibility

- `JobRunner`, `Registry`, and `AccessorFactory` keep their existing required method sets.
- Custom lifecycle runners that do not implement `ValidatingJobRunner` retain the existing
  stop-then-start flow.
- `ServiceFactory` remains source compatible. Executor and committee-verifier factories opt into
  the new `ServiceFactoryValidator` extension using their existing application config validation.
- No application config or `blockchain_infos` APIs change in this release.
