package observability

import (
	"context"
	"fmt"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

const configKey = "observability"

// Version is the observability component config schema version. Exactly this
// version is supported; configs declaring any other version are rejected.
const Version = 1

// Observability holds cross-cutting observability settings — the beholder
// monitoring config and the pyroscope profiling URL. These are consumed by both
// verifier and executor configs but are not part of the topology graph. The
// observability component publishes this as its phase output for the committeeccv
// and executor components to consume. The toml tags keep the serialized phased
// output stable.
type Observability struct {
	PyroscopeURL string                         `toml:"pyroscope_url"`
	Monitoring   ccvdeployment.MonitoringConfig `toml:"monitoring"`
}

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("observability component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decode(componentConfig)
	return err
}

// RunPhase1 publishes the cross-cutting observability settings (beholder
// monitoring + pyroscope URL) as a phase output for later phases to consume. It
// has no dependencies on other components and runs in Phase 1 alongside
// blockchains and jd.
//
// Output:
//   - "observability" — *Observability, read by the committeeccv and executor
//     components when generating verifier/executor configs.
func (c *component) RunPhase1(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
) (map[string]any, []devenvruntime.Effect, error) {
	obs, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{configKey: obs}, nil, nil
}

// config is the [observability] component config. Version is the component
// schema version; the remaining fields populate the published Observability.
type config struct {
	Version      int                            `toml:"version"`
	PyroscopeURL string                         `toml:"pyroscope_url"`
	Monitoring   ccvdeployment.MonitoringConfig `toml:"monitoring"`
}

func decode(raw any) (*Observability, error) {
	cfg, err := devenvruntime.DecodeConfig[config](raw, "observability")
	if err != nil {
		return nil, err
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return nil, err
	}
	return &Observability{
		PyroscopeURL: cfg.PyroscopeURL,
		Monitoring:   cfg.Monitoring,
	}, nil
}
