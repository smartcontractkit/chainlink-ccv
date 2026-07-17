package bootstrap

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	blockchainInfosKey = "blockchain_infos"
	monitoringKey      = "monitoring"
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

// GetAppConfig decodes the app config into the provided object. An error is returned if any
// fields other than the bootstrap-owned monitoring section are left undecoded. Monitoring remains
// accepted for compatibility with previously generated job specs; operator bootstrap config owns
// it and application decoders intentionally ignore it.
func (js JobSpec) GetAppConfig(cfg any) error {
	md, err := toml.Decode(js.AppConfig, cfg)
	if err != nil {
		return fmt.Errorf("error decoding app config: %w", err)
	}

	if hasTopLevelKey(md, blockchainInfosKey) {
		return fmt.Errorf("error decoding app config, %s is no longer supported", blockchainInfosKey)
	}

	var undecoded []string
	for _, key := range md.Undecoded() {
		if !strings.EqualFold(key[0], monitoringKey) {
			undecoded = append(undecoded, key.String())
		}
	}

	if len(undecoded) > 0 {
		return fmt.Errorf("error decoding app config, undecoded keys: %v", undecoded)
	}

	return nil
}

func hasTopLevelKey(md toml.MetaData, name string) bool {
	for _, key := range md.Keys() {
		if len(key) > 0 && strings.EqualFold(key[0], name) {
			return true
		}
	}
	return false
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
