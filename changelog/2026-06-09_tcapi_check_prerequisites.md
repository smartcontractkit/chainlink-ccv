# tcapi: CheckPrerequisites replaces HavePrerequisites

## Executive Summary

- `TestCase.HavePrerequisites(ctx) bool` is replaced by `CheckPrerequisites(ctx) ([]MissingPrerequisite, error)`.
- The old signature discarded all diagnostic information; callers could not tell why a test was skipped or whether the skip was expected.
- Affects every `tcapi.TestCase` implementation and every call site that gates test execution on prerequisite checks.
- Introduces a **breaking change**: the method is renamed and its return type changes completely.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `tcapi.TestCase.HavePrerequisites → tcapi.TestCase.CheckPrerequisites` | renamed + signature-changed | `\.HavePrerequisites\b` | `build/devenv/tests/e2e/tcapi/types.go:64` | [#haveprerequisites-renamed-to-checkprerequisites](#haveprerequisites-renamed-to-checkprerequisites) |
| `tcapi.MissingPrerequisite` | added | `MissingPrerequisite` | `build/devenv/tests/e2e/tcapi/types.go:30` | [#missingprerequisite-new-type](#missingprerequisite-new-type) |
| `basic.loadV3Env` | signature-changed | `loadV3Env\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:196` | [#loadv3env-return-type](#loadv3env-return-type) |

## Breaking Changes

### HavePrerequisites renamed to CheckPrerequisites

- **What changed:** `tcapi.TestCase` interface method `HavePrerequisites(ctx context.Context) bool`
- **Before:** `HavePrerequisites(ctx context.Context) bool`
- **After:** `CheckPrerequisites(ctx context.Context) ([]MissingPrerequisite, error)`
- **Why:** A `bool` return discards all information about *what* was missing. The new signature lets callers distinguish between "some expected component is absent" (non-empty `[]MissingPrerequisite`, skip gracefully) and "the check itself failed" (non-nil `error`, fail loudly).
- **Who is affected:** Every implementation of `tcapi.TestCase` and every caller that gates test execution on the prerequisite check.

## Migration Guide

1. **Rename the method** in every `TestCase` implementation from `HavePrerequisites` to `CheckPrerequisites` and update its signature:

```go
// Before
func (tc *myTestCase) HavePrerequisites(ctx context.Context) bool {
    return tc.ensureHydrated(ctx) == nil
}
```

```go
// After
func (tc *myTestCase) CheckPrerequisites(ctx context.Context) ([]tcapi.MissingPrerequisite, error) {
    return tc.ensureHydrated(ctx)
}
```

2. **Update `ensureHydrated`** (or equivalent internal function) to return `([]tcapi.MissingPrerequisite, error)`:

```go
// Before
func (tc *myTestCase) ensureHydrated(ctx context.Context) error {
    if !tc.hydrate(ctx, tc) {
        return fmt.Errorf("prerequisites not met")
    }
    tc.hydrated = true
    return nil
}
```

```go
// After
func (tc *myTestCase) ensureHydrated(ctx context.Context) ([]tcapi.MissingPrerequisite, error) {
    missing, err := tc.hydrate(ctx, tc)
    if err != nil {
        return nil, err
    }
    if len(missing) == 0 {
        tc.hydrated = true
    }
    return missing, nil
}
```

3. **Update the `hydrate` closure type** from `func(...) bool` to `func(...) ([]tcapi.MissingPrerequisite, error)`. Inside the closure:
   - Infrastructure failures (data store, chain selectors, registry lookups, sender address) → `return nil, fmt.Errorf("...")`
   - Contract/service lookups that may simply be absent → `append(missing, tcapi.MissingPrerequisite{Name: "...", Err: err})`

4. **Update `Run`** to handle the new `ensureHydrated` signature. When missing prerequisites are present, return them joined as a single error:

```go
// Before
func (tc *myTestCase) Run(ctx context.Context) error {
    if err := tc.ensureHydrated(ctx); err != nil {
        return err
    }
    // ...
}
```

```go
// After
func (tc *myTestCase) Run(ctx context.Context) error {
    missing, err := tc.ensureHydrated(ctx)
    if err != nil {
        return err
    }
    if len(missing) > 0 {
        errs := make([]error, len(missing))
        for i, m := range missing {
            errs[i] = m
        }
        return errors.Join(errs...)
    }
    // ...
}
```

5. **Update call sites** that gate test execution:

```go
// Before
if tc.HavePrerequisites(ctx) {
    t.Run(tc.Name(), func(t *testing.T) { ... })
} else {
    t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
}
```

```go
// After
if missing, err := tc.CheckPrerequisites(ctx); err != nil {
    t.Fatalf("prerequisite check failed for %s: %v", tc.Name(), err)
} else if len(missing) > 0 {
    t.Logf("Skipping %s: missing prerequisites: %v", tc.Name(), missing)
} else {
    t.Run(tc.Name(), func(t *testing.T) { ... })
}
```

## New Features / Additions

### MissingPrerequisite new type

`tcapi.MissingPrerequisite` is a new struct that represents a single expected-absent component in the environment:

```go
type MissingPrerequisite struct {
    Name string  // human-readable label, e.g. "contract receiver (default)"
    Err  error   // underlying lookup error
}

func (m MissingPrerequisite) Error() string // implements error
```

It implements the `error` interface so it can be used with `errors.Join` in `Run` and with testify assertions (`require.Empty(t, missing)`).

The distinction between `MissingPrerequisite` and the `error` return channel:
- `[]MissingPrerequisite` — the environment lacks an expected component; callers should skip the test without treating it as a failure.
- `error` — the prerequisite check itself could not complete (data store unavailable, unknown chain selector, missing registry); callers should fail loudly.

## References

- Prior changelog: `changelog/2026-05-18_simplify_tcapi.md`
