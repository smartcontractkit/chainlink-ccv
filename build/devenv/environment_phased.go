package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
)

// NewPhasedEnvironment creates a new CCIP CCV environment using the phased
// component runtime. It loads the raw TOML config, hands control to the
// runtime, then serializes the raw accumulated output map (minus runtime-only
// "_"-prefixed keys) to the env-out.toml file consumed by downstream tests. It
// returns the full accumulated output map.
func NewPhasedEnvironment() (out map[string]any, err error) {
	ctx := L.WithContext(context.Background())

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	rawConfig, err := loadRaw(configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Capture the schema version before the runtime consumes and deletes the
	// "version" key from rawConfig, so it can be re-emitted to the output file.
	var version int
	if v, ok := rawConfig["version"].(int64); ok {
		version = int(v)
	}

	// out is captured by the defer; its contents are available when the defer fires.
	defer func() {
		if ct, ok := out["_component_timings"].(*timing.ComponentTimeTracker); ok && ct != nil {
			// TODO: report component timings via DX tracker
			ct.Print(L)
		}
		var elapsed float64
		if timeTrack, ok := out["_time_track"].(*timing.TimeTracker); ok && timeTrack != nil {
			timeTrack.Print()
			elapsed = timeTrack.SinceStart().Seconds()
		}
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, elapsed)
	}()

	out, err = devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, devenvruntime.GlobalRegistry(), newDevenvEffectExecutor(), L)
	if err != nil {
		return nil, err
	}

	// Re-publish the schema version (the runtime consumed it) as a public output
	// key so the serialized file begins with version = N and LoadOutput can route
	// it to the correct decoder.
	out["version"] = version

	if err := storePhasedOutput(out); err != nil {
		return out, err
	}
	return out, nil
}

// stripPrivateKeys returns a copy of out with all "_"-prefixed keys removed.
func stripPrivateKeys(out map[string]any) map[string]any {
	public := make(map[string]any, len(out))
	for k, v := range out {
		if strings.HasPrefix(k, "_") {
			continue
		}
		public[k] = v
	}
	return public
}

// storePhasedOutput serializes the accumulated runtime output map to the
// env-out.toml file, stripping runtime-only keys (those prefixed with "_").
func storePhasedOutput(out map[string]any) error {
	public := stripPrivateKeys(out)
	return Store(&public)
}
