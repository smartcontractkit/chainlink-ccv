package chaos

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	ctfchaos "github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
)

const (
	// ExecPumbaTimeout is how long ExecPumba waits before returning. Zero means
	// fire-and-forget; the outage duration is controlled by the Pumba command.
	ExecPumbaTimeout = 0 * time.Second

	// DefaultOutageDuration is used for aggregator and verifier outage scenarios.
	DefaultOutageDuration = 20 * time.Second

	// ExecutorOutageDuration is used for executor and indexer outage scenarios.
	ExecutorOutageDuration = 30 * time.Second
)

// OutageSpec describes a container stop outage injected via Pumba before a test
// sends a message.
type OutageSpec struct {
	Duration time.Duration
	Targets  []string

	// LiteralSingle, when true with a single target, passes the container name to
	// Pumba without ^$ anchors (aggregator nginx behavior).
	LiteralSingle bool
}

// InjectOutage starts a Pumba container stop for the given spec and returns a
// cleanup function that tears down the Pumba sidecar.
func InjectOutage(ctx context.Context, spec OutageSpec) (func(), error) {
	if spec.Duration == 0 {
		spec.Duration = DefaultOutageDuration
	}
	cmd := BuildStopCommand(spec.Duration, spec.Targets, spec.LiteralSingle)
	zerolog.Ctx(ctx).Info().Str("pumbaCmd", cmd).Msg("injecting outage via Pumba")
	return ctfchaos.ExecPumba(cmd, ExecPumbaTimeout)
}
