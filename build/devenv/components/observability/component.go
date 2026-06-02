package observability

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml/v2"

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

// decode round-trips the raw TOML map[string]any into *Observability, verifying
// the declared component version.
func decode(raw any) (*Observability, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"observability"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding observability config: %w", err)
	}
	var wrapper struct {
		V config `toml:"observability"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding observability config: %w", err)
	}
	if err := devenvruntime.CheckConfigVersion(wrapper.V.Version, Version); err != nil {
		return nil, err
	}
	return &Observability{
		PyroscopeURL: wrapper.V.PyroscopeURL,
		Monitoring:   wrapper.V.Monitoring,
	}, nil
}
