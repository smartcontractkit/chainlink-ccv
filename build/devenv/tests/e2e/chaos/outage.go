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

	// DefaultOutageDuration is the default duration of a Pumba container stop outage if not specified in the spec.
	DefaultOutageDuration = 20 * time.Second
)

// OutageSpec describes a container stop outage injected via Pumba before a test
// sends a message.
type OutageSpec struct {
	Duration time.Duration
	// Targets are normalized Docker container names (leading "/" stripped) that Pumba
	// will stop during the outage. Resolve them with the container helpers in this
	// package (DefaultAggregatorNginx, VerifierContainers, ExecutorContainers,
	// ExecutorContainersForDest, IndexerContainer). Each target is matched against
	// running Docker container names via Pumba's re2 regex; see LiteralSingle for
	// anchor behavior.
	Targets []string
}

// InjectOutage starts a Pumba container stop for the given spec and returns a
// cleanup function that tears down the Pumba sidecar.
func InjectOutage(ctx context.Context, spec OutageSpec) (func(), error) {
	if spec.Duration == 0 {
		spec.Duration = DefaultOutageDuration
	}
	cmd := BuildStopCommand(spec.Duration, spec.Targets)
	zerolog.Ctx(ctx).Info().Str("pumbaCmd", cmd).Msg("injecting outage via Pumba")
	return ctfchaos.ExecPumba(cmd, ExecPumbaTimeout)
}
