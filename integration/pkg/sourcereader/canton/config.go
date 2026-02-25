package canton

const DefaultCantonConfigPath = "/etc/canton/config.toml"

// Config holds chain-specific configuration for the Canton chain integration.
// TODO: when this is moved to chainlink-canton, it doesn't have to be under the sourcereader package.
type Config struct {
	// ReaderConfigs is a map of canton chain selectors to reader configurations.
	ReaderConfigs map[string]ReaderConfig `toml:"reader_configs"`
}
