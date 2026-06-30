package bootstrap

import (
	"fmt"

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
}

// GetGenericConfig decodes the AppConfig field into chainaccess.GenericConfig.
//
// Deprecated: GenericConfig is where the blockchain_infos TOML table is defined.
// JD app config should not ship chain connection info (RPC URLs, etc.); that belongs
// in local config for standalone mode or node config for CL mode. Devenv still
// injects blockchain_infos through this decode path today. Prefer GetAppConfig for
// typed app-only config. GenericConfig should be fully deprecated once EVM swtich to use local config.
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
		if key[0] != "blockchain_infos" {
			undecoded = append(undecoded, key.String())
		}
	}

	if len(undecoded) > 0 {
		return fmt.Errorf("error decoding app config, undecoded keys: %v", undecoded)
	}

	return nil
}
