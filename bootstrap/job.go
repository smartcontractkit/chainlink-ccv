package bootstrap

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// JobSpec is the specification for a bootstrap service job, pushed by JD.
type JobSpec struct {
	Name          string `toml:"name"`
	ExternalJobID string `toml:"externalJobID"`
	SchemaVersion int    `toml:"schemaVersion"`
	Type          string `toml:"type"`
	AppConfig     string `toml:"appConfig"`

	// ConfigFieldName records which outer TOML field carried the app config in the source job
	// spec (for example "appConfig", "committeeVerifierConfig", or "executorConfig"). It is not
	// serialized. Devenv uses it to re-emit the same field when rebuilding a spec, so a rebuilt
	// spec keeps the field the target expects: standalone bootstrappers read appConfig, while CL
	// nodes require committeeVerifierConfig/executorConfig. Empty defaults to appConfig.
	ConfigFieldName string `toml:"-"`
}

// GetGenericConfig decodes the AppConfig field into chainaccess.GenericConfig.
//
// Deprecated: GenericConfig is where the blockchain_infos TOML table is defined.
// JD app config should not ship chain connection info (RPC URLs, etc.); that belongs
// in local config for standalone mode or node config for CL mode. This decoder remains
// only for legacy consumers. Prefer GetAppConfig for typed app-only config.
func (js JobSpec) GetGenericConfig() (chainaccess.GenericConfig, error) {
	var gcfg chainaccess.GenericConfig
	if _, err := toml.Decode(js.AppConfig, &gcfg); err != nil {
		return chainaccess.GenericConfig{}, fmt.Errorf("error decoding app config: %w", err)
	}
	return gcfg, nil
}

// GetAppConfig decodes the app config into the provided object. An error is returned
// if there are any fields aside from blockchain_infos that are left undecoded. See
// chainaccess.GenericConfig for details about why blockchain_infos is ignored.
func (js JobSpec) GetAppConfig(cfg any) error {
	md, err := toml.Decode(js.AppConfig, cfg)
	if err != nil {
		return fmt.Errorf("error decoding app config: %w", err)
	}

	// Deprecated: blockchain_infos should be dropped from appConfig, blockchain info will come from local config for standalone mode
	// or node config for cl-mode. Remove this filter once chain family repos stopped using blockchain_infos in appConfig.
	// Filter out undecoded fields under blockchain_infos.
	var undecoded []string
	for _, key := range md.Undecoded() {
		if key[0] != "blockchain_infos" && strings.ToLower(key[0]) != "monitoring" {
			undecoded = append(undecoded, key.String())
		}
	}

	if len(undecoded) > 0 {
		return fmt.Errorf("error decoding app config, undecoded keys: %v", undecoded)
	}

	return nil
}

// InnerConfig extracts the embedded inner config from a job spec wrapper. Exactly one of appConfig and the CL-mode config field must be set.
func InnerConfig(app, cl, clField string) (string, error) {
	if app != "" && cl != "" {
		return "", fmt.Errorf("job spec must set exactly one of appConfig and %s", clField)
	}
	if app != "" {
		return app, nil
	}
	if cl != "" {
		return cl, nil
	}
	return "", fmt.Errorf("job spec missing appConfig and %s", clField)
}
