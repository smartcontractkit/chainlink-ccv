---
name: Write Changelog
description: Write a concise developer changelog focused on breaking changes and new features with before/after examples
---

## Write Changelog

Write a changelog entry for the current branch or a specified set of commits.

### Steps

1. Determine scope: use `git log main..HEAD --oneline` (or the specified range) to identify commits.
2. For each changed file, use `detect_changes` to identify what shifted and its risk level.
3. Identify breaking changes: anything that removes or renames a public symbol, changes a function signature, alters config structure, or requires a migration step.
4. Identify new features: new public APIs, new CLI flags, new config fields, new behaviour behind existing APIs.
5. Skip internal refactors, test-only changes, and lint fixes unless they affect callers.
6. Write the file to `changelog/YYYY-MM-DD_<slug>.md` using today's date (check current date from the environment or `date +%F`).

### Output Format

```
# <Short title — what shipped>

## Summary

One or two sentences. What changed and why.

---

## Breaking change: <what broke>

<Concise explanation. One paragraph max.>

| What | Before | After |
|------|--------|-------|
| ... | ... | ... |

Before:
```go
// old usage
```

After:
```go
// new usage
```

---

## New: <feature name>

<Concise explanation.>

```go
// minimal usage example
```

---

## Bug fixes

- **<Component>**: one-line description.

---

## Recommended additions  *(optional)*

- Doc or test gaps worth filing.
```

### Rules

- **Brief**: each section should fit on a screen. Cut prose, not examples.
- **Examples first**: before/after code blocks beat paragraph explanations.
- **Breaking changes go first**, even if there are many new features.
- **Omit sections** that have no content — don't write empty headers.
- File name slug is lowercase, words separated by underscores, ≤5 words (e.g. `2026-04-27_executor_jd_migration.md`).
- Use the before/after table for structural changes (config shape, struct fields, interface methods); use code blocks for API or invocation changes.
