# Operator policy hook on the committee verifier

## Executive Summary

- The committee verifier gains an optional `[policy_hook]` config section: one operator-owned
  HTTPS endpoint the node calls once per message as the last check before signing, after finality,
  after the curse and message-disablement checks, and after the node's own checks on the message.
  A message the node was never going to sign is dropped without a call. HTTP 200 with `PASS`
  signs and attests exactly as before. HTTP 200 with `FAIL` drops the message permanently on that
  node, like an RMN curse, recoverable only by an operator replay. Any other outcome (4xx, 5xx,
  timeout, unreachable host, unparseable body, or a response whose `message_id` echo names a
  different message) retries and never drops.
- A FAIL withholds one node's signature; it does not by itself stop the message. The committee's
  threshold still decides, so stopping a message takes `N - threshold + 1` of the committee's `N`
  nodes rejecting it. Whether the hook is an effective control is therefore a committee-topology
  question, and `verifier/docs/policy_hook.md` says so under "What a FAIL stops".
- The signed payload and signature are byte-identical with and without the hook. Nothing from the
  endpoint's response is signed, so the aggregator and the wire format are untouched.
- The endpoint contract is published as OpenAPI 3.0.3 at `verifier/policy_hook_openapi_v1.yaml`
  and versioned from v1. `verifier/pkg/policy` holds the Go types, the HTTP client, and the
  `GatedVerifier` wrapper; `TestOpenAPISpecMatchesContract` fails if the two drift.
- v1 supports exactly one endpoint per verifier. An operator who runs several checks aggregates
  them behind their own endpoint, which keeps one call mapping to one verdict.
- Deployment: the hook is set per NOP in the environment topology
  (`[environment_topology.nop_topology.nops.policy_hook]`) and emitted into that NOP's verifier
  job spec by `ApplyVerifierConfig`. A NOP without the section gets the same job spec bytes as
  before this change.
- Devenv: the `ccv-fakes` container serves a fake policy endpoint with a test control surface,
  `standard.policy-hook.profile` enables the hook on both NOPs of the default committee, and
  `TestE2ESmoke_PolicyHook` covers pass, outage with retry, and reject with replay against a real
  committee. The test runs from `test-smoke.yaml`.
- Observability: message transitions gain stage `policy` with outcomes `policy_passed`,
  `policy_rejected`, `policy_unavailable`, and `policy_skipped` (the node's own checks rejected the
  message, so no call was made); message failures classify as `policy_rejected` or
  `policy_endpoint_error`; the node logs `Dropping task - policy hook returned FAIL` and
  `Policy hook verdict unavailable, scheduling retry` per message.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.Config.PolicyHook` | added | `PolicyHook \*policy\.Config` | `verifier/pkg/commit/config.go:227` | [#config-section](#config-section) |
| `policy.Config` | added | `type Config struct` | `verifier/pkg/policy/config.go:67` | [#config-section](#config-section) |
| `policy.WrapVerifier` / `policy.NewGatedVerifier` / `policy.GatedVerifier` | added | `policy\.WrapVerifier\(` | `verifier/pkg/policy/gate.go:287` | [#gate](#gate) |
| `vtypes.TaskValidator` / `commit.Verifier.ValidateTask` | added | `TaskValidator interface` | `verifier/pkg/vtypes/interfaces.go:45` | [#gate](#gate) |
| `policy.Checker` / `policy.HTTPChecker` | added | `NewHTTPChecker\(` | `verifier/pkg/policy/client.go:55` | [#gate](#gate) |
| `policy.EvaluateRequest` / `policy.EvaluateResponse` / `policy.MessageV1` / `policy.TokenTransferV1` | added | `NewEvaluateRequest\(` | `verifier/pkg/policy/contract.go:125` | [#contract](#contract) |
| `verifier/policy_hook_openapi_v1.yaml` | added | `policy-evaluate` | `verifier/policy_hook_openapi_v1.yaml` | [#contract](#contract) |
| `ccvdeployment.NOPConfig.PolicyHook` | added | `toml:"policy_hook,omitempty"` | `deployment/topology.go:94` | [#deployment](#deployment) |
| `changesets.NOPInput.PolicyHook` | added | `PolicyHook:\s+nop\.PolicyHook` | `deployment/changesets/inputs.go:26` | [#deployment](#deployment) |
| `monitoring.MessageTransitionStagePolicy` and the `Policy*` outcome, reason, and failure-class constants | added | `MessageTransition(Stage\|Outcome\|Reason)Policy` | `verifier/pkg/monitoring/metrics.go:24` | [#observability](#observability) |
| `standard.policy-hook.profile` / `env-policy-hook.toml` | added | `policy-hook` | `build/devenv/` | [#devenv](#devenv) |
| `fakes/pkg/policy.API` (fake endpoint and control API) | added | `/policy/v1/control` | `build/devenv/fakes/pkg/policy/api.go` | [#devenv](#devenv) |
| `logasserter.MessageDroppedByPolicyHook` / `logasserter.PolicyHookVerdictUnavailable` | added | `MessageDroppedByPolicyHook\(` | `build/devenv/tests/e2e/logasserter/log_stages.go:22` | [#devenv](#devenv) |
| `TestE2ESmoke_PolicyHook` | added | `TestE2ESmoke_PolicyHook` | `build/devenv/tests/e2e/smoke_policy_hook_test.go:36` | [#devenv](#devenv) |

## Breaking Changes

None. A verifier with no `[policy_hook]` section runs the same code path as before (`WrapVerifier`
returns the commit verifier unchanged), its job spec is byte-identical, and there is no aggregator,
wire-format, or database change.

## Migration Guide

Nothing to do unless a NOP wants the hook. To enable it, add the section to that NOP's topology
entry and re-apply the verifier config:

```toml
[[environment_topology.nop_topology.nops]]
alias = "acme-verifier-1"
name = "acme-verifier-1"
  [environment_topology.nop_topology.nops.policy_hook]
  base_url = "https://policy.internal.acme.example"
  request_timeout = "5s"
  retry_delay = "10s"
```

`base_url` is required and must be `https` unless `insecure_connection = true`, which exists for
local development against a plain-HTTP fake. A malformed section fails config validation at job
load, not at the first message. Operator-facing documentation is in `verifier/docs/policy_hook.md`.

## New Features / Additions

### config-section

`commit.Config.PolicyHook *policy.Config` (`toml:"policy_hook,omitempty"`). `policy.Config` has
`base_url`, `request_timeout` (default 5s, rejected above `policy.MaxRequestTimeout` of 15s),
`retry_delay` (default 10s), `insecure_connection`, and `require_auth`. The timeout ceiling exists because a batch
of up to 50 messages evaluated 8 at a time is up to seven sequential waves of calls, and a batch
that outruns the task queue's two-minute job lock is reclaimed and evaluated a second time. Durations are strings because the Chainlink node decodes the committee
verifier config with go-toml, which does not decode duration strings into `time.Duration`.
`commit.Config.Validate` calls `policy.Config.Validate`. The documented config at
`docs/config/verifier/committee/config.documented.toml` carries the section, and the configdoc
registry populates it so `TestConfigDocsFresh` covers it.

`require_auth` makes a missing endpoint credential fatal at startup rather than a call that goes out
unauthenticated. It is checked in `policy.WrapVerifier`, not in `policy.Config.Validate`, because
that validation also runs where a job spec is built rather than run, on a machine that holds no
verifier secrets. No credential material goes in this section: it is marshaled into the job spec and
stored in Job Distributor.

### wire contract decisions

Two things about the published shape, both settled before v1 goes out because neither is cheap to
change afterwards.

Chain selectors are decimal strings, not JSON numbers. A JSON number is a float64 in JavaScript and
in most schema-generated clients, exact only to 2^53, and 64 of the 250 registered chain selectors
are above 2^63 alone, so an endpoint parsing one as a number corrupts it silently. The token
`amount` was already a string for the same reason. Counters a real chain bounds (block numbers,
sequence numbers, gas limits) stay JSON numbers. `indexer/pkg/client/internal/client.go` is the
worked example of getting this wrong: generated from `format: int64`, its `Message` model types
both selectors as Go `int64`.

`endpoint_url` is now `base_url`, and the verifier POSTs to `base_url` + `policy.EvaluatePath`
(`/v1/evaluate`) rather than to the configured URL verbatim. A base may carry a path prefix, so an
endpoint behind a gateway that routes on one is configured as `https://acme.example/compliance` and
serves `/compliance/v1/evaluate`. A base that already ends in `/v1/evaluate` and a base with a query
string are both rejected at startup. Posting the URL verbatim was the one shape a client generated
from the spec could not produce, since a generated client appends the operation path to a base.

### authentication

Authentication of the verifier to the endpoint is optional and off unless a credential is
configured. When one is, `hmac.SignHTTPRequest` adds the three headers the aggregator scheme already
uses (`protocol/common/hmac`): `authorization` with the API key, `x-authorization-timestamp` with a
millisecond epoch, and `x-authorization-signature-sha256` with an HMAC-SHA256 over
`POST <request-target> <sha256-hex-of-body> <api-key> <timestamp-ms>`. The request target is
`URL.RequestURI()`, so a gateway prefix carried in `base_url` is covered by the signature. The signer is new in `protocol/common/hmac`, as the
HTTP counterpart of the gRPC `NewClientInterceptor` already there: one scheme, one implementation
per transport, so an operator implements one thing and there is one place to review.

`policy.ResolveCredential(fileCred)` reads the pair from the verifier secrets file's new
`[policy_hook]` table (`vsecrets.PolicyHookSecret`, exposed by `VerifierSecrets.PolicyHookSecret()`).
The file is the only source: the aggregator and database credentials read environment variables for
deployments that predate the file, and a credential added after it has no such history to keep. An
entirely absent pair returns `(nil, nil)` because authentication is optional; a half-supplied pair is
an error rather than a silent downgrade. Errors name the field, never the value.
`docs/config/verifier/secrets.documented.toml` carries the table.

### `NewVerificationCoordinator` policy credential (additive, not breaking)

`cmd/verifier/servicefactory.go` resolves the credential from the secrets file. The Chainlink-node
path has no secrets file, so `constructors.NewVerificationCoordinator` accepts one from its caller,
as it already does for the aggregator credentials. It arrives as a variadic option rather than a
parameter, because the constructor's only caller lives in the Chainlink node repo and the two repos
cannot land a signature change at the same instant:

```go
vc, err := constructors.NewVerificationCoordinator(
    lggr, cfg, aggregatorSecrets, signingAddress, signer, relayers, ds,
    constructors.WithPolicyHookCredential(cred), // new, optional
)
```

Existing call sites are unchanged and keep compiling. Omitting the option calls the endpoint
unauthenticated, which is also what an absent credential does in the standalone path; a
`[policy_hook]` section that sets `require_auth` with no credential fails construction, which is
the point of that setting.

### gate

`policy.WrapVerifier(lggr, verifierID, inner, cfg, monitoring, cred)` returns `inner` unchanged for a nil
config and a `*GatedVerifier` otherwise. Both constructors (`cmd/verifier/servicefactory.go` and
`integration/pkg/constructors/committee_verifier.go`) call it, so the enable condition lives in one
place. `GatedVerifier.VerifyMessages` evaluates a batch against the endpoint with at most 8 calls in
flight, forwards the passing tasks to the wrapped verifier, and returns exactly one result per task:
a FAIL becomes a non-retryable `VerificationError` (the task verifier fails and archives the job),
an endpoint error becomes a retryable one carrying `retry_delay`, jittered per message across half
to one and a half times the configured value. The jitter matters because an outage stalls every
message a node is holding at once and a fixed delay reschedules them all onto the same tick, which
sends the whole backlog at a failing endpoint together on every retry. The delay does not grow with
the attempt count: that needs the queue's `attempt_count` on the task and is tracked separately.

The call is the last check before signing. `commit.Verifier` implements the new optional
`vtypes.TaskValidator` interface (`ValidateTask`), and `NewGatedVerifier` picks it up with a type
assertion on the verifier it wraps, so no wiring at either construction site changed. A task
`ValidateTask` rejects skips the endpoint entirely and is forwarded to the wrapped verifier, which
fails it with its own error and the same accounting an ungated verifier produces. The gate never
synthesizes that error, so there is no second rejection path to keep in step.

The gate cannot call the commit verifier's checks directly: `verifier/pkg/commit/config.go` imports
`verifier/pkg/policy` for the config type, so the dependency only goes one way. The optional
interface is what gets the ordering without inverting that, and it keeps `GatedVerifier` generic
over `vtypes.Verifier`: a wrapped verifier that does not implement `TaskValidator` gets a call per
task, exactly as before.

`commit.Verifier.ValidateTask` and `verifyMessage` share one implementation
(`resolveSignablePayload`) on purpose, and `TestValidateTask_AgreesWithVerifyMessages` pins them
together. The asymmetry is the reason: a `ValidateTask` looser than verification only wastes a call,
but a `ValidateTask` stricter than verification would skip the endpoint on a message that then gets
signed, which is a message signed without the operator's endpoint ever seeing it.

`HTTPChecker` is a dedicated client rather than a reuse of `verifier/pkg/token/http`. The token
client folds every non-200 into one opaque error and shares a cool-down per URL, and the gate needs
the opposite: "unavailable" and "rejected" are the difference between a retry and a drop. It posts
JSON, does not follow redirects, reads at most 64 KiB of body, and treats a decision other than
`PASS` or `FAIL` as an error.

### contract

`policy.NewEvaluateRequest(verifierID, task)` builds the v1 request from a `VerificationTask`:
`schema_version`, `verifier_id`, `message_id`, `source_tx_hash`, `source_block_number`,
`finalized_block_number`, `block_depth`, and the decoded message with an optional token transfer.
Byte fields are `0x`-prefixed hex, an empty byte field is `"0x"`, and token amounts are decimal
strings. `MessageV1` and `TokenTransferV1` are deliberate copies of the wire message so the
published contract stays frozen when `protocol.Message` gains fields. The spec file follows the
same alphabetical key layout as `indexer/indexer_opanapi_v1.yaml`.

`EvaluateResponse` carries an optional `message_id` that echoes the request. Nothing else in a
response ties a verdict to the message it answers, so an endpoint that sets it lets the verifier
refuse a verdict crossed by a cache or a proxy; a mismatch is an error and retries, and an endpoint
that omits the field is unaffected. `decision` is matched exactly for `PASS` and
case-insensitively for `FAIL`, because reading a verdict as unusable costs a retry while reading one
as `PASS` costs a signature. The schemas do not set `additionalProperties: false`, so either side
can add a field inside v1 without a version bump.

The `decision` enum carries a third value, `HOLD`, which is reserved and not implemented. It is
published so that adding the behavior later is additive for an endpoint that validates strictly
against the enum, rather than a breaking change. `parseDecision` refuses it by name with an error
pointing at the supported alternative, so an endpoint that returns it early has its message retried
rather than signed or dropped. `TestOpenAPISpecEnums` asserts both halves - the value stays in the
spec and the client keeps rejecting it - so the reservation cannot quietly become a live verdict.
The supported way to hold a message for review is to answer `FAIL` while the review is open and
replay the message once it clears.

The spec declares the optional authentication scheme under `components.securitySchemes` with a
top-level `security` of `[{}, {all three headers}]`, which is how OpenAPI spells "either
unauthenticated or fully signed".

`finalized_block_number` and `block_depth` come from a new
`vtypes.VerificationTask.FinalizedBlockAtReady`, captured in the source reader when the message
meets its finality requirement. The pre-existing `FinalizedBlockAtRead` is captured at discovery,
when the message's own block is still ahead of the finalized head, so a depth computed from it was
0 for every message that took the normal path to finality.

### deployment

`ccvdeployment.NOPConfig.PolicyHook` decodes `[environment_topology.nop_topology.nops.policy_hook]`.
`NOPInputsFromTopology` copies it onto `changesets.NOPInput.PolicyHook`, and `buildVerifierJobSpecs`
sets `commit.Config.PolicyHook` from it. The executor changeset ignores the field.

### observability

Metrics reuse the bounded message-transition counter: stage `policy`, outcomes `policy_passed`,
`policy_rejected`, `policy_unavailable`, `policy_skipped`, reasons `policy_rejected`,
`policy_endpoint_error`, and `task_invalid`. The four outcomes add up to the messages that entered
the stage, so a skipped message does not leave a silent gap between what arrived and what was
evaluated. A message counted `policy_skipped` then fails on the node's own error, so it classifies
under that error rather than under a policy class; a rising `policy_skipped` is an upstream problem,
not a policy one.
`monitoring.ClassifyError` maps `policy hook rejected` to `policy_rejected` and the endpoint,
request, and response errors to `policy_endpoint_error`. Failed and dropped jobs are archived, so
`ccv job-queue` on the node lists a rejected message with the endpoint's reason as its error.

### devenv

`build/devenv/fakes/pkg/policy` registers `POST /policy/v1/evaluate` on the shared fake data
provider, plus `POST /policy/v1/control` (`default_decision`, `reason`, `reject`, `force_status`,
`reset`) and `GET /policy/v1/control/calls`. The fake is written against the published spec rather
than the verifier's Go types, so it exercises the same wire contract an operator would and the fakes
module does not take on the verifier's dependency graph. It answers 400 to any `schema_version`
other than `v1`, so a contract drift surfaces as a message that never attests.
`env-policy-hook.toml` restates the NOP list from `env.toml` (an overlay replaces an array of
tables) with the hook on `default-verifier-1` and `default-verifier-2`, and
`standard.policy-hook.profile` stacks it on `env-src-auto-mine.toml`. The log asserter learns
`MessageDroppedByPolicyHook` (checked before the generic `Dropping task` stage, which it would
otherwise match) and `PolicyHookVerdictUnavailable`.

## Compatibility & Requirements

- Recovering a dropped message is an operator action on every committee member that dropped it.
  The failed job sits in the task-verifier archive, so `ccv job-queue reschedule --message-id` on
  a running node moves it back to the active queue and the node asks the endpoint again. A range
  of messages is replayed with the checkpoint-rewind flow instead: stop the node, run
  `ccv chain-statuses set-finalized-height` for the source chain, and restart. A friendlier replay
  UX is tracked separately.
- Retries are bounded by the task queue's 7-day retry window. A message still without a verdict
  when that passes is failed the same way a rejected one is.
- A FAIL stops a message only if enough of the committee also rejects it; see the summary above.
- The endpoint's `reason` string is logged and stored as the archived job's error for the 30-day
  retention period, so it reaches wherever the node's logs ship. It should carry a case reference
  rather than the customer data behind the decision.
- Authentication is optional and off unless a credential is configured, and there is exactly one
  scheme. The recommended deployment is still to run the endpoint inside the verifier's own cluster
  and not expose it. An endpoint that checks signatures should be paired with `require_auth = true`
  on the verifier, so a credential that fails to reach the container is a boot failure rather than
  every message on the lane retrying against a 401 until the 7-day deadline.
- `HOLD` is reserved in the response enum and not implemented. Endpoints must not return it.
- `gopkg.in/yaml.v3` moves from an indirect to a direct dependency of the root module, used by
  `verifier/pkg/policy/openapi_test.go` to parse the spec.
