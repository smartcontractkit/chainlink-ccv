# configdoc quickstart

`configdoc` generates config/secrets documentation directly from your Go config
structs, using the structs' **doc comments as the single source of truth**. It
TOML-encodes a fully-populated instance of each config and injects each field's
Go doc comment above the emitted key, producing a working, annotated
`*.documented.toml` per structure.

You get, for free:

- **One source of truth** — docs live in the doc comment on the field, nowhere else.
- **A freshness check** — a normal unit test fails CI if a committed doc drifts
  from the struct (no Docker/DB dependency).
- **A completeness gate** — generation hard-errors if a documented field has no
  doc comment, so you can't add a field without describing it.

This guide gets you generating docs for your own repo in ~15 minutes.

---

## Prerequisites

Your repo must already depend on the `chainlink-ccv` Go module (most chain
integration repos do). The engine is imported as:

```go
import "github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
```

**One hard constraint:** doc comments are only harvested for packages **inside
your own module**. A config field whose *type* lives in a different module will
be emitted without a comment and trip the completeness gate. Keep your config
structs — and the nested types they reference — within your module.

---

## Step 1 — Document your config structs

Put a doc comment on every field you want documented. One line is plenty; the
first token is rewritten to the TOML key automatically, so write it naturally:

```go
package ccip

// Config holds the chain-specific configuration for the CCIP integration.
type Config struct {
	// ReaderConfigs maps a chain selector to its reader configuration.
	ReaderConfigs map[string]ReaderConfig `toml:"reader_configs"`
	// GRPCLedgerAPIURL is the gRPC endpoint of the Canton ledger API.
	GRPCLedgerAPIURL string `toml:"grpc_ledger_api_url"`
}
```

`GRPCLedgerAPIURL is the gRPC endpoint...` renders as
`# grpc_ledger_api_url is the gRPC endpoint...` above the key.

Every field needs a `toml:"..."` tag — the injector matches comments to keys by
tag. Fields tagged `toml:"-"` are excluded.

---

## Step 2 — Declare your targets

Create a small registry package. For each config/secrets structure, write a
`New()` builder returning a fully-populated, valid instance, and register a
`configdoc.Target`.

```go
// tools/configdocs/registry/registry.go
package registry

import (
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/smartcontractkit/chainlink-canton/ccip"
)

var Targets = []configdoc.Target{
	{
		Name: "canton",
		Out:  "canton/config.documented.toml", // path under your docs root
		Kind: configdoc.KindConfig,             // or configdoc.KindSecrets
		New:  cantonConfig,
	},
}

// cantonConfig returns the instance to document. Populate required fields with
// illustrative values; the values you set become the documented example values.
func cantonConfig() any {
	return &ccip.Config{
		GRPCLedgerAPIURL: "grpc://canton-ledger:5001",
		ReaderConfigs: map[string]ccip.ReaderConfig{
			"1": { /* ... */ },
		},
	}
}
```

### Rules for a good `New()` builder

- **Run your real defaulting routine** if you have one (e.g. `SetDefaults()`,
  `GetNormalizedConfig()`), so defaults appear in the docs.
- **Pin non-deterministic values.** If defaulting fills something from
  `os.Hostname()` or a clock, set it explicitly — otherwise the output changes
  between runs and the freshness test flaps.
- **Allocate pointer sub-structs** you want documented. The encoder omits `nil`
  pointers and `nil` maps, so `&Config{Sub: &SubConfig{...}}`, and give maps at
  least one entry to document their shape.
- **Use obviously-fake placeholders for secrets** (`"<api-key>"`,
  `postgres://user:password@host/db`). These are examples, not real credentials.

---

## Step 3 — Add the command

The command body is a single call. `configdoc.Main` owns flag parsing (`-o`
output dir, `-check` verify mode), locates your module via the nearest `go.mod`,
and writes or verifies the docs.

```go
// tools/configdocs/main.go
package main

import (
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/smartcontractkit/chainlink-canton/tools/configdocs/registry"
)

func main() { configdoc.Main(registry.Targets) }
```

Generate (run from your repo root, so the tool can read your source tree):

```bash
go run ./tools/configdocs -o docs/config
```

Add a recipe so it's one command. Pick whichever your repo uses:

**Justfile**

```just
config-docs:
    go run ./tools/configdocs -o docs/config
```

**Makefile** (recipe lines must be tab-indented)

```make
.PHONY: config-docs config-docs-check

config-docs:
	go run ./tools/configdocs -o docs/config

# Verify the committed docs are up to date (for CI / pre-commit).
config-docs-check:
	go run ./tools/configdocs -o docs/config -check
```

---

## Step 4 — Add the freshness test

This is what enforces the docs in CI. It regenerates every target and diffs
against the committed file — a plain unit test, no external dependencies.

```go
// tools/configdocs/registry/registry_test.go
package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/stretchr/testify/require"
)

func TestConfigDocsFresh(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	g, err := configdoc.NewGenerator(cwd) // walks up to your go.mod
	require.NoError(t, err)

	stale, err := g.Check(Targets, filepath.Join(g.ModuleRoot, "docs", "config"))
	require.NoError(t, err)
	for _, s := range stale {
		verb := "out of date"
		if s.Missing {
			verb = "missing"
		}
		t.Errorf("%s is %s; run: just config-docs", s.Target.Out, verb)
	}
}
```

Because it runs under `go test ./...`, it's picked up by your existing test CI
with no extra workflow. You can also gate a pre-commit hook or CI step on
`go run ./tools/configdocs -check`, which exits non-zero on drift.

---

## Daily workflow

1. Change a config struct or a doc comment.
2. Run `just config-docs` (or `make config-docs`).
3. Commit the regenerated `docs/config/**` alongside the code change.

If you forget step 2, CI fails with `... is out of date; run: just config-docs`.
That message hard-codes `just`; if your repo uses Make, read it as
`make config-docs`.

---

## API reference

| Symbol | Purpose |
| --- | --- |
| `configdoc.Main(targets)` | One-line command entrypoint: parse flags, build a Generator, write or `-check`. |
| `configdoc.NewGenerator(dir)` | Build a `*Generator`, auto-detecting the module root/path from the nearest `go.mod`. |
| `Generator.Write(targets, outDir)` | Render every target and write it under `outDir`. Returns the written paths. |
| `Generator.Check(targets, outDir)` | Render every target and diff against committed files. Returns the stale/missing ones. |
| `Generator.Render(target)` | Render a single target to a string (rarely needed directly). |
| `configdoc.Target` | `{Name, Out, Kind, New}` — one config/secrets structure to document. |
| `configdoc.DocKind` | `KindConfig` or `KindSecrets` (selects header wording only). |

`Target.New` is `func() any` and must return a pointer to your struct.

---

## Troubleshooting

| Message | Cause / fix |
| --- | --- |
| `TypeName.FieldName: missing doc comment` | A documented field has no doc comment. Add a one-line comment, or drop the field from the config with `toml:"-"`. |
| `unknown TOML key "X" in TypeName` | The encoder emitted a key the injector can't map back to a field — usually a field with no `toml` tag, or a type in another module (see the in-module constraint). |
| `... is out of date` in CI | You changed a struct/comment but didn't regenerate. Run `just config-docs` / `make config-docs` and commit. |
| Field missing from the output entirely | It's a `nil` pointer/map or an `omitempty` zero value — populate it in your `New()` builder so the encoder emits it. |
| Freshness test flaps between runs | A non-deterministic value (hostname, timestamp, map iteration) leaked into `New()`. Pin it to a fixed illustrative value. |

---

## How it works (one paragraph)

`New()` produces a real, valid config instance. The engine TOML-encodes it (the
encoder does all the structure/value walking), then walks the encoded lines and,
for each key or table, resolves the originating struct field by reflection and
prepends that field's Go doc comment. Freshness is a regenerate-and-diff; the
`New()` instance is both the documented values and the oracle the docs are
checked against. There is no per-repo rendering code — only your doc comments,
your `New()` builders, and the one-line command.
