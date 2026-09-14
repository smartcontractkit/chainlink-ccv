# Policy hook is standalone-verifier only

## Executive Summary

- The operator policy hook is supported on the standalone verifier only. A verifier running inside
  a Chainlink node now rejects a `[policy_hook]` section at startup instead of gating traffic with
  an endpoint call it cannot authenticate.
- `constructors.WithPolicyHookCredential` and `constructors.VerificationCoordinatorOption` are
  removed, and `NewVerificationCoordinator` loses its variadic `opts ...` parameter. No caller
  passed an option, so the signature change is source-compatible.
- The credential the hook signs with is resolved from the verifier secrets file's `[policy_hook]`
  table. A verifier inside a Chainlink node has no such file. The credential was going to have to
  be threaded in from the node repo, and until it was, the section booted a hook that called the
  operator's endpoint unauthenticated: the endpoint answers 401, the verifier reads that as
  "verdict unknown", and every message on the lane retries until the queue's 7-day deadline. That
  is a worse outcome than refusing to boot.
- `ApplyVerifierConfig` rejects a `cl`-mode NOP that carries a `[policy_hook]`, so the unsupported
  combination fails while the topology is still editable instead of shipping a job spec the node
  cannot load.
- No change to the standalone verifier: same wire contract, same config, same behavior. Nothing in
  `verifier/pkg/policy` changed.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `constructors.NewVerificationCoordinator` | behavior-changed | `func NewVerificationCoordinator\(` | `integration/pkg/constructors/committee_verifier.go:41` | [#rejection-at-boot](#rejection-at-boot) |
| `constructors.WithPolicyHookCredential` / `constructors.VerificationCoordinatorOption` | removed | `WithPolicyHookCredential\(` | `integration/pkg/constructors/options.go` (deleted) | [#rejection-at-boot](#rejection-at-boot) |
| `changesets.buildVerifierJobSpecs` | behavior-changed | `policy hook is supported on a standalone` | `deployment/changesets/apply_verifier_config.go:504` | [#rejection-at-plan-time](#rejection-at-plan-time) |

## Breaking Changes

`constructors.WithPolicyHookCredential` and `constructors.VerificationCoordinatorOption` are gone,
along with the variadic `opts ...VerificationCoordinatorOption` parameter on
`NewVerificationCoordinator`. The option shipped in `2026-08-27_verifier_policy_hook.md` and no
caller adopted it, so existing call sites keep compiling unchanged.

A Chainlink-node verifier whose job spec carries `[policy_hook]` no longer starts. That
configuration was never usable: it called the operator's endpoint unauthenticated.

## Migration Guide

Nothing to do for a verifier with no `[policy_hook]` section, which is every deployment that has
not opted into the hook.

To run the hook, run the standalone verifier. In a JD deployment that means the NOP carrying the
section is in `standalone` mode:

```toml
[[environment_topology.nop_topology.nops]]
alias = "acme-verifier-1"
name = "acme-verifier-1"
mode = "standalone"
  [environment_topology.nop_topology.nops.policy_hook]
  base_url = "https://policy.internal.acme.example"
```

`ApplyVerifierConfig` fails if a NOP carries a hook without that mode, so the mismatch surfaces
while the topology is still editable rather than as a job the node cannot load. An unset `mode`
defaults to `cl` and is rejected the same way.

## Rejection at boot

`NewVerificationCoordinator` returns
`invalid ccv verifier configuration: [policy_hook] is not supported on a verifier running inside a
Chainlink node; run the standalone verifier to use the policy hook` when `cfg.PolicyHook != nil`,
and logs it under the same `Invalid CCV verifier configuration.` line the constructor's other
config failures use.

The check runs before `cfg.Validate()`, which validates the section's own fields. A malformed hook
on an entry point where no hook is valid should say the section is unsupported, not that its
`base_url` is wrong.

The constructor no longer calls `policy.WrapVerifier`. With the section rejected, the wrap was a
no-op that returned the commit verifier unchanged, so the coordinator takes `commitVerifier`
directly. `cmd/verifier/servicefactory.go` — the standalone path — still calls `WrapVerifier` with
the credential from the secrets file, and is the only construction site with a gate.

## Rejection at plan time

`buildVerifierJobSpecs` errors with
`NOP %q has a [policy_hook] but runs in %q mode; the policy hook is supported on a standalone verifier only`
when a NOP resolves to `cl` mode and carries the section. Without it the changeset would emit a
well-formed spec that the node rejects at job load, which puts the failure on the operator's node
rather than on the plan they can still change.

`build/devenv/env-policy-hook.toml` already sets `mode = "standalone"` on both hooked NOPs, so
`TestE2ESmoke_PolicyHook` is unaffected.
