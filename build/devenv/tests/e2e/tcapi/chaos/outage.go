package chaos

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	ctfchaos "github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
)

const (
	// ExecPumbaTimeout is how long ExecPumba waits before returning. Zero means
	// fire-and-forget; the outage duration is controlled by the Pumba command.
	ExecPumbaTimeout = 0 * time.Second

	// DefaultOutageDuration is the default duration used for Pumba outages and latency injections when not specified in the spec.
	DefaultOutageDuration = 20 * time.Second
)

// OutageSpec describes a container stop outage injected via Pumba before a test
// sends a message.
type OutageSpec struct {
	Duration time.Duration
	// Targets are normalized Docker container names (leading "/" stripped) that Pumba
	// will stop during the outage.
	Targets []string
}

// InjectOutage starts a Pumba container stop for the given spec and returns a
// cleanup function that tears down the Pumba sidecar. Pumba is a short-lived
// sidecar that issues docker stop + auto-restart via the Docker API; the cleanup
// callback removes the sidecar.
func InjectOutage(ctx context.Context, spec *OutageSpec) (func(), error) {
	if spec == nil {
		return nil, errors.New("outage spec is nil")
	}
	duration := spec.Duration
	if spec.Duration == 0 {
		duration = DefaultOutageDuration
	}
	if len(spec.Targets) == 0 {
		return nil, errors.New("no targets specified")
	}
	cmd := BuildStopCommand(duration, spec.Targets)
	zerolog.Ctx(ctx).Info().Str("pumbaCmd", cmd).Msg("injecting outage via Pumba")
	return ctfchaos.ExecPumba(cmd, ExecPumbaTimeout)
}

// LatencySpec describes a network latency injection via Pumba netem before a
// test sends a message.
type LatencySpec struct {
	// Duration is how long the latency injection lasts. If zero, a default of 20s is used.
	Duration time.Duration
	// Delay is the injected latency in milliseconds.
	Delay int
	// Targets are normalized Docker container names (leading "/" stripped) that
	// Pumba will apply netem delay to.
	Targets []string
}

// injectLatency starts a Pumba netem delay for the given spec and returns a
// cleanup function that tears down the Pumba sidecar.
func injectLatency(ctx context.Context, spec LatencySpec) (func(), error) {
	if spec.Duration == 0 {
		spec.Duration = DefaultOutageDuration
	}
	if spec.Delay <= 0 {
		return nil, errors.New("latency delay must be positive")
	}
	if len(spec.Targets) == 0 {
		return nil, errors.New("no targets specified")
	}
	cmd := BuildNetemDelayCommand(spec.Duration, spec.Delay, spec.Targets)
	zerolog.Ctx(ctx).Info().Str("pumbaCmd", cmd).Msg("injecting latency via Pumba")
	return ctfchaos.ExecPumba(cmd, ExecPumbaTimeout)
}
