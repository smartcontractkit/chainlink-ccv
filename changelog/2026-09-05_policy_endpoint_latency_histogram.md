# Policy endpoint latency histogram

## Executive Summary

- `verifier_policy_http_request_duration_seconds` times each call to the operator's policy
  endpoint, labeled with the same `policy_passed` / `policy_rejected` / `policy_unavailable`
  vocabulary the stage's transition counter uses, so the two read side by side. A `policy_skipped`
  task makes no call and never appears.
- The outcome counters only count. An endpoint drifting from 200ms to 4s is invisible on them
  until it crosses `request_timeout` and starts failing; this histogram shows it while messages
  are still passing.
- Buckets run 1ms to 15s. 15s is `policy.MaxRequestTimeout`, the largest per-call timeout an
  operator may configure, so a call that runs to the ceiling lands in a real bucket rather than
  `+Inf`.
- `vtypes.MetricLabeler` gains `RecordPolicyHTTPRequestDuration`. See Breaking Changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `vtypes.MetricLabeler.RecordPolicyHTTPRequestDuration` | added | `RecordPolicyHTTPRequestDuration\(` | `verifier/pkg/vtypes/interfaces.go:220` | [#the-interface-method](#the-interface-method) |
| `monitoring.VerifierMetricLabeler.RecordPolicyHTTPRequestDuration` | added | `policyHTTPRequestDurationSeconds` | `verifier/pkg/monitoring/metrics.go:965` | [#the-histogram](#the-histogram) |
| `policy.callOutcome` | added | `func callOutcome\(` | `verifier/pkg/policy/gate.go:213` | [#the-histogram](#the-histogram) |

## Breaking Changes

`vtypes.MetricLabeler` gains one method, `RecordPolicyHTTPRequestDuration`. The interface is
exported, so an implementation outside this repo stops compiling until it adds the method.

All five implementations in this repo are updated: `monitoring.VerifierMetricLabeler`,
`monitoring.FakeVerifierMetricLabeler`, `testutil.NoopMetricLabeler`, the generated
`mocks.MockMetricLabeler`, and the test noop in `verifier/pkg/helpers_test.go`. The alternative
shape, an optional interface picked up by type assertion, was not taken: `MetricLabeler` is a
single flat surface of ~25 recording methods with one production implementation, and splitting the
newest one out would leave the caller branching on whether metrics exist for a path where they
always do.

## The histogram

`GatedVerifier.evaluateAll` times each `checker.Evaluate` call and records it against the message's
labels. `callOutcome` maps the call to its label: an error is `policy_unavailable`, a FAIL verdict
is `policy_rejected`, anything else is `policy_passed`. An error wins over whatever verdict came
back with it, since a verdict that arrived with an error is not one the gate acts on.

The instrument is registered in `InitMetrics` and its buckets in `MetricViews`. The top boundary
is named as a literal rather than imported from `policy.MaxRequestTimeout`: `verifier/pkg/policy`
already depends on `verifier/pkg/monitoring`, so the import would cycle.

## The interface method

The method takes the outcome as a string rather than a typed enum, matching
`IncrementMessageTransition` next to it. The doc comment names the
`monitoring.MessageTransitionOutcomePolicy*` constants as the vocabulary, and
`TestGatedVerifier_RecordsEndpointLatencyPerOutcome` pins the three the gate actually emits, so a
label renamed on the counter and not here would fail rather than silently split a dashboard.
