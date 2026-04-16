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

func (js JobSpec) GetGenericConfig() (chainaccess.GenericConfig, error) {
	var gcfg chainaccess.GenericConfig
	if _, err := toml.Decode(js.AppConfig, &gcfg); err != nil {
		return chainaccess.GenericConfig{}, fmt.Errorf("error decoding app config: %w", err)
	}
	return gcfg, nil
}

func (js JobSpec) GetAppConfig(cfg any) error {
	md, err := toml.Decode(js.AppConfig, cfg)
	if err != nil {
		return fmt.Errorf("error decoding app config: %w", err)
	}

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
