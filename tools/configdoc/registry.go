package configdoc

import (
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// DocKind distinguishes config docs from secrets docs (affects header wording).
type DocKind int

const (
	KindConfig DocKind = iota
	KindSecrets
)

// Target is one documentation target. It is the single place a doc is declared.
type Target struct {
	// Name identifies the target (e.g. "executor").
	Name string
	// Out is the output path relative to the docs root.
	Out string
	// Kind selects config vs secrets header wording.
	Kind DocKind
	// New returns the fully-populated instance to document: defaults applied,
	// illustrative values for required fields. This single instance replaces
	// per-field example tags and a separate defaulting adapter — it is both the
	// documented values and the freshness oracle.
	New func() any
}

// Targets is the registry of documentation targets. Only the executor is wired
// up so far (see docs/adr/0011); the remaining apps are added incrementally.
var Targets = []Target{
	{Name: "executor", Out: "executor/config.documented.toml", Kind: KindConfig, New: executorDocInstance},
}

// executorDocInstance builds a fully-populated, valid executor Configuration
// (illustrative values for required fields) and runs the executor's real
// defaulting (GetNormalizedConfig) to fill defaulted fields. The Monitoring
// field is left zero: it is a deprecated, bootstrap-sourced concern (documented
// separately), so its inlined section shows only zero-value defaults here.
func executorDocInstance() any {
	c := &executor.Configuration{
		IndexerAddress: []string{"http://indexer-1:8080", "http://indexer-2:8080"},
		ExecutorID:     "executor-1",
		ChainConfiguration: map[string]executor.ChainConfiguration{
			"1": {
				DestinationChainConfig: chainaccess.DestinationChainConfig{
					OffRampAddress: "0x00000000000000000000000000000000000000ff",
					RmnAddress:     "0x00000000000000000000000000000000000000ab",
				},
				DefaultExecutorAddress: "0x00000000000000000000000000000000000000ec",
				ExecutorPool:           []string{"executor-1", "executor-2"},
			},
		},
	}
	normalized, err := c.GetNormalizedConfig()
	if err != nil {
		panic("configdoc: executor documented instance is invalid: " + err.Error())
	}
	return normalized
}
