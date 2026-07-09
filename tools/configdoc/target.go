package configdoc

// DocKind distinguishes config docs from secrets docs (affects header wording).
type DocKind int

const (
	KindConfig DocKind = iota
	KindSecrets
)

// Target is one documentation target: a single config or secrets structure to
// render. It is repo-agnostic — each repo declares its own Targets and hands
// them to a Generator. The engine never references any particular repo's structs.
type Target struct {
	// Name identifies the target (e.g. "executor"). Used in the doc header.
	Name string
	// Out is the output path relative to the docs root (e.g. "executor/config.documented.toml").
	Out string
	// Kind selects config vs secrets header wording.
	Kind DocKind
	// New returns the fully-populated instance to document: defaults applied,
	// illustrative values for required fields. This single instance is both the
	// documented values and the freshness oracle — there are no per-field example
	// tags or a separate defaulting adapter.
	New func() any
}
